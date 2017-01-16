var token = require("./token");
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
          hasAnActiveSessionByUsername(req), 
          autenticateWithUsrAndPwd(req)
        ];
        Promise.all(promisesNewSession).then(function(allData) {
            
            /*
            * Write payload to sessions file. This helps in controlling the
            * number of active sessions.
            */
            debug('Saving token from usr/pwd autentication');
            saveSession(allData[1].payload).then(function(data) {
                req.jwt = allData[1].jwt;
                next();
            }, function(err) {
                debug(err);
                req.error = err;
                next();
            });
            
        }, function(err) {
            debug(err);
            req.error = err;
            next();
        });
        
    }
    else if (strategy === TOKEN_STRATEGY) {

        var promisesNewSession = [
          checkJWTPresentedAsCredential(req), 
          hasAnActiveSessionByToken(req),
          authenticateWithJwt(req)
        ];
        Promise.all(promisesNewSession).then(function(allData) {
            
            /*
            * Write payload to sessions file. This helps in controlling the
            * number of active sessions.
            */
            debug('Saving new token from JWT autentication');
            saveSession(allData[2].payload).then(function(data) {
                req.jwt = allData[2].jwt;
                next();
            }, function(err) {
                debug(err);
                req.error = err;
                next();
            });
            
        }, function(err) {
            debug(err);
            req.error = err;
            next();
        });

    } else {
        req.error =  new Error("Unable to determine authentication strategy.");
        next();
    }
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
                    aud: req.janoConf.appName,
                    ipaddr: req.ip,
                    roles: data.roles
                }
                
                var keyFile = req.janoConf.keysFolder+'/'+req.janoConf.appName+'.pem';
                debug('keyFile: %s', keyFile);

                var result = token.sign(payload, keyFile);
                result.payload.isActive = true;
                
                debug('authentication successful');
                resolve( result );
                
            }, function(err) {
                debug(err);
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
 *  valid (not expired)
 */ 
var hasAnActiveSessionByToken = function(req) {
    return new Promise(function(resolve, reject){
        var jwt_token = req.params.token || req.query.token;
    
        if (!jwt_token) {
            reject(new Error("Token credential not provided as param or query property"));
            return;        
        }
    
        var decoded_jwt = token.decode(jwt_token);
        if (!decoded_jwt) {
            reject(new Error("Token credential decodification error"));
        }
        
        var result = sessions.where(function(obj) {
            return (obj.sub === decoded_jwt.sub) && (obj.isActive == true);
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
 *  Checks the user (username parameter in body request) has been issued a 
 *  signed JWT and its valid (not expired)
 */ 
var hasAnActiveSessionByUsername = function(req) {
    return new Promise(function(resolve, reject){
        var username = req.body.username;
        if (!username) {
            reject(new Error("Error checking current sessions. Username not provided in request body."));
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
 *  Checks if the requestor has presented a discarded JWT (discarded by the user
 *  when signs out, or a JWT from another App used to sign in in this app)
 */ 
var checkJWTPresentedAsCredential = function(req) {
    return new Promise(function(resolve, reject){

        var jwt_token = req.params.token || req.query.token;
    
        if (!jwt_token) {
            reject(new Error("Token credential not provided as param or query property"));
            return;        
        }
    
        var decoded_jwt = token.decode(jwt_token);
        if (!decoded_jwt) {
            reject(new Error("Token credential decodification error"));
        }

        // First validate the JWT signature
        var sourceAppKeyFile = req.janoConf.keysFolder+'/'+decoded_jwt.payload.iss+'_public.pem';
        var claimsToValidate = {
            'aud': req.janoConf.appName
        }
        
        try {
            token.verify(jwt_token,sourceAppKeyFile, claimsToValidate);
        } catch(err) {
            debug(err);
            reject(new Error("Token validation failed"));
        }
        
        // Second validates if the JWT has been invalidated/discarded
        var result = sessions.where(function(obj) {
            return (obj.uuid === decoded_jwt.uuid) && (obj.isActive == false);
        });
        
        
        if (result && result.length > 0){
            reject(new Error("JWT represents an already discarded session."));
        }
        
        /*
         * At this point the JWT used as credential is valid and has not been
         * Discarded. Creation of a new signed JWT may proceed, but first this
         * JWT credential itself is to be marked as discarded.
        */
        decoded_jwt.payload.isValid = false;
        debug('Saving token from JWT autentication');
        saveSession(decoded_jwt.payload).then(function (data) {
            resolve(true);
        }, function(err) {
            debug(err);
            reject(new Error("Error saving user session"));
        })
    })
}

/**
 * Saves the token in the in-memmory db 
 */
var saveSession = function(sessionObj) {
    return new Promise(function(resolve, reject){
        if (!sessionObj) {
            reject(new Error("El objeto a almacenar no es valido"))
        }
        else {
            debug('Object to save %s', JSON.stringify(sessionObj));
            sessions.insert(sessionObj);
            resolve(true);
        }
    });
} 

/**
 * Authenticate a user using a JWT previusly issued by this app o other app.
 * 
 * Promise should resolve the signed jwt.
 */ 
var authenticateWithJwt = function(req) {
    
    return new Promise(function(resolve, reject) {

        debug("Authenticating with token");
    
        var jwt_token = req.params.token || req.query.token;
    
        if (!jwt_token) {
            reject(new Error("Token credential not provided as param or query property"));
            return;        
        }
        
        var decoded_jwt = token.decode(jwt_token);
        if (!decoded_jwt) {
            reject(new Error("Token credential decodification error"));
        }
        
        //validates user, calling provided user function 'checkUserFn'
        if (req.janoConf.checkUserFn) {
            req.janoConf.checkUserFn(decoded_jwt.payload.sub).then(function (data){
                //proceeds to create a new JWT and sign it
                if (!data.subject || !data.roles) {
                    reject(new Error("'checkUserFn' did not resolve required data for JWT: subject and/or roles."));
                    return;
                }
                
                var new_payload = {
                    sub: data.subject,
                    iss: req.janoConf.appName,
                    aud: req.janoConf.appName,
                    ipaddr: req.ip,
                    roles: data.roles
                }
                
                var thisAppPrivateKeyFile = req.janoConf.keysFolder+'/'+req.janoConf.appName+'.pem';
                debug('private key file: %s', thisAppPrivateKeyFile);

                var result = token.sign(new_payload, thisAppPrivateKeyFile);
                debug('authentication successful');

                result.payload.isActive = true;
                resolve( result );                    

            }, function(err) {
                debug(err);
                reject(new Error("Error during user/roles validation"));
            });
        } else {
            reject(new Error("No checkUserFn defined"));
        }
        
        
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
