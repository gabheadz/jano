var jwt = require('jsonwebtoken');
const uuidV4 = require('uuid/v4');

module.exports = {
  /**
  * Takes an object payload and a private cert and generates a signed JWT.
  *
  * @param  {object} payload
  * @param  {String} private cert
  * @return {String} jwt
  */
  sign: function(payload, cert) {
    
    var options = {
      algorithm: "RS256",
      expiresIn: "1h"
    };
    
    if (!payload || payload === undefined) {
      throw new Error('Payload not defined');
    }
    
    if (!payload.iss || payload.iss === undefined) { 
      throw new Error('No \'issuer\' defined in payload');
    }
    
    if (!payload.sub || payload.sub === undefined) { 
      throw new Error('No \'subject\' defined in payload');
    }
    
    if (!payload.ipaddr || payload.ipaddr === undefined) { 
      throw new Error('No \'ipaddr\' defined in payload');
    }
    
    if (!cert || cert === undefined) {
      throw new Error('invalid certificate');
    }
    
    payload.uuid = uuidV4();

    var token = jwt.sign(payload, cert, options);
    
    return token;

  },

  /**
   * Takes a signed JWT and a private cert and verifies its signature. On success, this
   * function returns the jwt payload
   *
   * @param  {String} signed jwt
   * @param  {String} the private cert
   * @return {object} the object payload
   */
  verify: function(token, cert, iss) {
    
    if (!token || token === undefined) { 
      throw new Error('invalid token string');
    }
    
    if (!cert || cert === undefined) { 
      throw new Error('invalid certificate');
    }
    
    var options = {
      algorithms: ['RS256']
    }
    
    if (iss) {
      options.issuer = iss;
    }
    
    return jwt.verify(token, cert, options);
    
  }
};