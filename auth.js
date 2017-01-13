var token = require("./token");
var fs = require("fs");
var Promise = require("bluebird");

const debug = require('debug')('jano');

const USR_PWD_STRATEGY = 'USR_PWD';
const TOKEN_STRATEGY = 'JWT_TOKEN';

var db;
var sessions;
          
var getSessionsCollection = function(req, res) {
    if (!db)
        db = req.janoConf.db;
    if (db && !sessions) {
        sessions = db.getCollection('janoSessions');
        if (!sessions)
            sessions = db.addCollection('janoSessions');
    }
    return sessions != null;
}

/**
 * Function that process a login request. It depends on the 'authenticateFn' defined
 * in jano Config.
 * 
 */
var signIn = function(req, res, next) {
    
    if (!getSessionsCollection(req, res)) {
        req.error = new Error("Could not create db or session collection");
        next();
    }
    
    var strategy = determineAuthenticationStrategy(req);
    if (strategy === USR_PWD_STRATEGY) {
        
        var promisesNewSession = [
          hasAnActiveSession(req), 
          autenticateWithUsrAndPwd(req)
        ];
        Promise.all(promisesNewSession).then(function(allData) {
            
            /*
            * Write payload to sessions file. This helps in controlling the
            * number of active sessions.
            */
            saveSession(req, allData[1].payload).then(function(data) {
                req.jwt = allData[1].jwt;
                next();
            }, function(err) {
                req.error = err;
                next();
            });
            
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

/**
 * Determine the kind of login request being issued
 */
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

/**
 * Authenticate a user using username and password. Relies on 'authenticateFn'
 * defined in jano config.
 */ 
var autenticateWithUsrAndPwd = function(req) {
    
    return new Promise(function(resolve, reject){
            
        debug("Authenticating with username and password");
        
        var username = req.body.username;
        var password = req.body.password;
        
        if (!username || !password) {
            reject(new Error("Username and/or password credentials not provided in request body."));
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
                
                var keyFile = req.janoConf.keysFolder+'/'+req.janoConf.appName+'.pem';
                debug('keyFile: %s', keyFile);
                var cert = fs.readFileSync(req.janoConf.keysFolder+'/'+req.janoConf.appName+'.pem');  // get private key
                debug('authentication successful');
    
                var result = token.sign(payload, cert);
                result.payload.isActive = true;
                resolve( result );
                
            }, function(err) {
                console.log(err);
                reject(err);
            });
        }
        else {
            reject(new Error("No 'authenticateFn' provided."));
        }
    });
}

/**
 *  Checks the user (subject in the jwt) has been issued a signed JWT and it is
 *  valid (not expired) or discarded by the user when signs out (active = false)
 */ 
var hasAnActiveSession = function(req) {
    return new Promise(function(resolve, reject){
        var username = req.body.username;
        if (!username) {
            reject(new Error("Username and/or password credentials not provided in request body."));
            return;
        }
        
        var result = sessions.where(function(obj) {
            return (obj.sub === username) && (obj.isActive == true);
        });
        
        if (!result)
            resolve({'activeSessions': false});
        else if (result.length == 0)
            resolve({'activeSessions': false});
        else {
            reject(new Error("User already have an active session."));
        }
    })
}

/**
 * Saves the token in the in-memmory db 
 */
var saveSession = function(req, sessionObj) {
    return new Promise(function(resolve, reject){
        sessions.insert(sessionObj);
        resolve('session inserted into collection');
    });
} 

/**
 * Authenticate a user using a JWT previusly issued by this app o other app.
 */ 
var authenticateWithJwt = function(req) {
    
    return new Promise(function(resolve, reject) {

        debug("Authenticating with token");
    
        var token = req.params.token || req.query.token;
    
        if (!token) {
            reject(new Error("Token credential not provided as param or query property"));
            return;        
        }
        
        reject(new Error("Not Implemented yet"));
    });
}

/**
 * Function that signs out an user (mark a session in the in-memmory db isActive = false), 
 * rendering the JWT unusable for further requests.
 */ 
var signOut = function(req, res, next) {
    
    var session =  sessions.findOne({ uuid: req.credentials.uuid });
    debug('session to sign out', session);
    if (session) {
        session.isActive = false;
    }
    sessions.update(session);

    next();
}

module.exports =  { 
    signIn: signIn,
    signOut: signOut
}
