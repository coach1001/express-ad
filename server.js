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
    cors = require('cors'),
    moment = require('moment');

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

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());

app.get('/', function(req, res) {});

app.get('/groupusers/:index', function(req, res) {
    var app_groups = serverConfig.app_ldap_groups_role_mapping;
    var ad_group = '';
    var group_users = [];

    app_groups.map( function (group, index){
        console.log(parseInt(req.params.index,10),index);
        if(parseInt(req.params.index,10) === index){            
            if(ad_group === ''){            
                ad_group = group.group;    
            }            
        }
        return group;
    });

    ad.getUsersForGroup(ad_group, function(err, users) {
      if (err) {
        console.log('ERROR: ' +JSON.stringify(err));
        return;
      }

      if (! users) console.log('Group: ' + ad_group + ' not found.');
      else {
        users.map( function(user){
            group_users.push({value: user.sAMAccountName, label: user.displayName, email: user.mail});
            return user;
        });
        res.json(group_users);
      }
    });

});

app.post('/adlogin', function(req, res) {

    var username = req.body.email;
    var password = req.body.pass;    
    var username_fqdn = '';
    
    
    if(username.split('@')[1]){
        username_fqdn = username;
        username = username.split('@')[0];        
    }else{
        username_fqdn = username+serverConfig.app_ldap_domain_suffix;
    }

    
    ad.authenticate(username_fqdn, password, function(err, auth) {

        if (err) {
            if (err.code === 49) {
                res.status(401).json({message: 'Invalid Credentials'});
            } else {
                res.status(501).json({message: 'AD Server Error, Contact Administrator'});
            }
        } else if (auth) { //LDAP Auth Successfull																	
            var groups_ = [];
            var app_groups = serverConfig.app_ldap_groups_role_mapping;
            var role = '';
            var user = {};
            
            ad.findUser(username_fqdn, function(err, user) {//FIND USER
                //console.log(user);

                ad.getGroupMembershipForUser(username_fqdn, function(err, groups) {//GET GROUPS                    
                    
                    if (err) {//ROLE 
                        console.log('ERROR: ' +JSON.stringify(err));
                        return;
                    }
                    if (! groups){                
                        console.log('User: ' + email + ' not found.');
                    }                  
                    else{                                            
                        groups.map( function(g){
                            app_groups.map(function(ap){                            
                                if(g.cn === ap.group){                                
                                    if(role === ''){
                                        role = ap.role;
                                    }
                                }
                                return ap;
                            });
                            return g;
                        });                    
                    }//ROLE        
                    
                    if(role === ''){
                        res.status(401).json({message:'You are not Authorized to use this Application'});
                    }
                    else {    
                            GetAppUser(username, function(error, users) {//CREATE OR LOGIN
                            
                            if (users.length > 0 && !error) {//LOGIN
                                UpdateAppADUserEmail({username: users[0].username, email: user.mail},function(err,result){
                                    if(err){
                                        res.status(500).json({message: 'Rest API Service Error, Contact Administrator'});
                                    }else{
                                        var payload = {                         
                                            username: users[0].username, 
                                            email: user.mail,                            
                                            role: role,
                                            verified: users[0].verified,
                                            logged_in_time: moment().format("YYYY-MM-DDTHH:mm:ss.SSS")
                                        };

                                        jwt.sign(payload, serverConfig.app_rest_jwt_secret, {}, function(err, result) {                            
                                            if(err){
                                                res.status(500).json({message: 'JWT Creation Error, Contact Administrator'});          
                                            }else{                            
                                                res.json({token: result});    
                                            }                                    
                                        });
                                    }                            
                                
                                });                        
                                                                   
                            } else if(!error){//CREATE                                                                        
                                CreateAppADUser({username:username, email: user.mail, role: role}, function(error,user_) {                                                                            
                                    if(error){
                                        res.status(500).json({message: 'Rest API Service Error, Contact Administrator'});
                                    }else{
                                        var payload = {                                     
                                                username: user_[0].username, 
                                                email: user_[0].email,                                                                            
                                                role: role,
                                                verified: user_[0].verified,
                                                logged_in_time: moment().format("YYYY-MM-DDTHH:mm:ss.SSS")
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

                        })//CREATE OR LOGIN
                    }
                });//GET GROUPS
            })//FIND USER

        }else{ //LDAP Auth Failed
            res.status(401).json(authResponses.invalidCredentials);
        }    
    });

});

var UpdateAppADUserEmail = function(data, callback) {

    var appRequest_OPT_ = extend({}, appRequest_OPT);
    appRequest_OPT_.url = appRequest_OPT_.url + serverConfig.app_rest_update_ldap_email_url;
    appRequest_OPT_.json = { username_: data.username, email_: data.email};

    request.post(appRequest_OPT_, function(err, res, body) {
        if (err) {                        
            callback(true,[])
        } else {            
            callback(false,body);
        }
    });
};

var CreateAppADUser = function(data, callback) {
    console.log(data);
    var appRequest_OPT_ = extend({}, appRequest_OPT);
    appRequest_OPT_.url = appRequest_OPT_.url + serverConfig.app_rest_create_ldap_user_url;
    appRequest_OPT_.json = { username_: data.username, email_: data.email, role_: data.role };

    request.post(appRequest_OPT_, function(err, res, body) {
        if (err) {                        
            callback(true,[])
        } else {            
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
        adConfig.username = serverConfig.app_ldapbind_user;
        adConfig.password = serverConfig.app_ldapbind_password;

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
