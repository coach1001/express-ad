var express = require('express'),
    bodyParser = require('body-parser'),
    ActiveDirectory = require('activedirectory'),
    serverConfig = require('./server_config.json'),
    request = require('request'),
    ldapdb = {},
    token = {},
    extend = require('util')._extend,
    dns = require('dns'),
    jwt = require('jsonwebtoken'),
    cors = require('cors');

var app = express();
var ad = {};

var adConfig = {
    url: '',
    baseDN: ''
};

var appLogin_OPT = {
    method: 'POST',
    json: {}
};

var appRequest_OPT = {};

var authResponses = {
    
    invalidCredentials: {
        code: 49,
        status: -1,
        description: 'Authentication Failed, Invalid Credentials'
    },
    ldapServerError: {
        code: "ENETUNREACH",
        status: -2,
        description: 'Authentication Failed, LDAP Server Offline'
    }
};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());

app.get('/', function(req, res) {});

app.post('/adlogin', function(req, res) {

    var username = req.body.email;
    var password = req.body.pass;    
    var email = '';
    
    
    if(username.split('@')[1]){
        email = username;
        username = username.split('@')[0];        
    }else{
        email = username+serverConfig.app_ldap_domain_suffix;
    }

    
    ad.authenticate(email, password, function(err, auth) {

        if (err) {
            if (err.code === 49) {
                res.status(401).json({message: 'Invalid Credentials'});
            } else {
                res.status(501).json({message: 'AD Server Error, Contact Administrator'});
            }
        } else if (auth) { //LDAP Auth Successfull																	

            GetAppUser(username, function(error, users) {
                if (users.length > 0 && !error) {
                    
                    var logged_in_time = new Date();
                    var utcDate = logged_in_time.toUTCString();
                    
                    var payload = { 
                        id: users[0].id,
                        username: users[0].username, 
                        email: users[0].email,
                        role: users[0].role,
                        verified: users[0].verified,
                        logged_in_time: utcDate
                    };

                    jwt.sign(payload, serverConfig.app_rest_jwt_secret, {}, function(err, result) {                            
                        if(err){
                            res.status(500).json({message: 'JWT Creation Error, Contact Administrator'});          
                        }else{                            
                            res.json({token: result});    
                        }                                    
                    });

                } else if(!error){
                    
                    console.log('Creating...');

                    CreateAppADUser({username:username, email: email, role: serverConfig.app_rest_signup_role}, function(error,user) {                        
                        
                        
                        if(error){
                            res.status(500).json({message: 'Rest API Service Error, Contact Administrator'});
                        }else{
                            var payload = { 
                                    id: user.id,
                                    username: user.username, 
                                    email: user.email,
                                    role_: serverConfig.app_rest_signup_role
                                };

                                jwt.sign(payload, serverConfig.app_rest_jwt_secret, {}, function(err, result) {                            
                                    if(err){
                                        res.status(500).json({message: 'JWT Creation Error, Contact Administrator'});          
                                    }else{
                                        res.json({token: result});    
                                    }                                    
                                });
                            }
                    })
                    

                } else if(error){
                    res.status(500).json({message: 'Rest API Service Error, Contact Administrator'});
                }
            })


        } else { //LDAP Auth Failed
            res.status(401).json(authResponses.invalidCredentials);
        }
    });

});

var CreateAppADUser = function(data, callback) {

    var appRequest_OPT_ = extend({}, appRequest_OPT);
    appRequest_OPT_.url = appRequest_OPT_.url + serverConfig.app_rest_create_ldap_user_url;
    appRequest_OPT_.json = { username: data.username, email: data.email, role_: data.role };

    request.post(appRequest_OPT_, function(err, res, body) {
        if (err) {
            callback(true,[])
        } else {
            console.log(body);
            callback(false,body);
        }
    });
};

var GetAppUser = function(username, callback) {

    var appRequest_OPT_ = extend({}, appRequest_OPT);
    appRequest_OPT_.url = appRequest_OPT_.url + serverConfig.app_rest_get_ldap_users_url + '?username=eq.' + username;
    appRequest_OPT_.json = {};

    request.get(appRequest_OPT_, function(err, res, body) {
        
        if (err) {            
            callback(true,{});
        } else {
            callback(false,body);
        }
    })

};

var RunServer = function() {
    var server = app.listen(8081, function() {
        var host = server.address().address;
        var port = server.address().port;
        console.log("App listening at http://%s:%s", host, port);
    })
};

var GetAppLdapUserJwt_r = function() {
    var appLogin_OPT_ = extend({}, appLogin_OPT);

    appLogin_OPT_.json.email = serverConfig.app_dbldap_user;
    appLogin_OPT_.json.pass = serverConfig.app_dbldap_password;
    appLogin_OPT_.url = appLogin_OPT_.url + serverConfig.app_rest_login_url;

    console.log('Connecting to Application Backend...!')

    request.post(appLogin_OPT_, function(err, res, body) {
        if (err) {

            setTimeout(function() {
                console.log('Failed to Connect to Application Backend, Retrying...!')
                GetAppLdapUserJwt_r();
            }, 2000);

        } else {
            console.log('Connected to Application Backend...!')            
            token = body.token;
            console.log(token);
            appRequest_OPT.headers = { 'Authorization': 'Bearer ' + token }
            RunServer();
        }
    });

};

var aResolveServers_r = function(fqdn, callback) {
    dns.lookup(fqdn, function(err, addresses, family) {
        if (addresses) {
            callback(addresses);
        } else {
            aResolveServers_r(fqdn, function(addresses_) {
                callback(addresses_);
            })
        }
    })
};

var InitializeServer = function() {

    console.log('Preparing to Run Server...!');
    console.log('Resolving Auxilary Servers using Host Names...!');
    console.log('Attempting to Resolve Active Directory...!');

    aResolveServers_r(serverConfig.app_ldap_host, function(result) {
        console.log('Active Directory Resolved to', result, '...!');
        console.log('Attempting to Resolve Rest Server...!');

        adConfig.url = 'ldap://' + result;
        adConfig.baseDN = serverConfig.app_ldap_base_dn;
        ad = new ActiveDirectory(adConfig);

        aResolveServers_r(serverConfig.app_rest_host, function(result_) {
            console.log('Rest Server Resolved to', result_, '...!');

            appLogin_OPT.url = 'http://' + result_ + ':' + serverConfig.app_rest_port;
            appRequest_OPT.url = 'http://' + result_ + ':' + serverConfig.app_rest_port;
            GetAppLdapUserJwt_r();
        })
    })
};

InitializeServer();
