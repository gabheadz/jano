var fs = require("fs");
var Promise = require("bluebird");

/*
* User function to perform authentication against an user repo.
*/
exports.authenticateUserAgainstRepo = function(username, password) {
    return new Promise(function(resolve, reject){
        if (!username || !password) {
            reject(new Error("username and/or password not provided"));
        }
        else {
            //TODO: Connect to an user repository (ex:ldap) and check user/password
            //TODO: Get user groups, and translate them into roles

            //if successful, return an jSON object with the subject and roles.
            //Jano will use this info in the payload signed into the JWT
            resolve({ 
                'subject': username, 
                'roles': ['role1', 'role2'], 
                'email': username+'@localdomain.com',
                'name' : 'FirstName Middlename LastName'
            })
            
            //TODO: if authentication not successful reject with an error:
            
            //reject(new Error("Wrong username and/or password"));
            //reject(new Error("Unexpected error during login process"));
        }
	});
};
    

/*
* User function to check if an user exists/is valid in the user repo. 
* It is not an authentication.
*/
exports.isValidUserInRepo = function(username) {
    return new Promise(function(resolve, reject){
        if (!username) {
            reject(new Error("username not provided"));
        }
        else {
            //TODO: Connect ldap and check if user is valid
            //TODO: Get user groups, and translate them into roles
            
            //if user is valid, return an jSON object with the subject and roles.
            //Jano will use this info in the payload signed into the JWT
            resolve({ 
                'subject': username, 
                'roles': ['role1', 'role2'], 
                'email': username+'@localdomain.com',
                'name' : 'FirstName Middlename LastName'
            })
            
            //TODO: if user is not valid reject with an error object:
            
            //req.error = new Error("Not a Valid user");
            //req.error = new Error("Unexpected error during user validation process");
        }
    });
};

