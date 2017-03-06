var	express 					= require('express'),
		bodyParser 				= require('body-parser'),
		ActiveDirectory 	= require('activedirectory'),		
		serverConfig			= require('./server_config.json'),
		request						= require('request'),
		ldapdb						= {},		
		token							= {},
		extend 						= require('util')._extend,
		dns								= require('dns'),
		jwt 							= require('jsonwebtoken');

var app = express();
var ad = {};

var adConfig = {
	url : '',
	baseDN : ''
};

var appLogin_OPT = {	
	method : 'POST',	
	json : {}
};

var appRequest_OPT = {				
};

var authResponses = {
	invalidCredentials : {
		code : 49,
		status : -1,
		description : 'Authentication Failed, Invalid Credentials'
	},
	ldapServerError : {
		code : "ENETUNREACH",
		status : -2,
		description : 'Authentication Failed, LDAP Server Offline'
	}
};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.get('/', function (req, res) {   
});

app.post('/ldap_login',function(req,res){
	
	var username = req.body.email;
	var password = req.body.pass;
	
	var authorized = {
		code : 1,
		status : 1,		
		description : 'Authentication Successfull'
	};

	ad.authenticate(username,password,function(err,auth){	
		
		if(err){			
			if(err.code === 49){
				res.json(authResponses.invalidCredentials);
			}else{
				res.json(authResponses.ldapServerError);
			}		
		}else if(auth){ //LDAP Auth Successfull																	
			
			aGetAppUser_r(username,function(users){							
				
				if(users.length > 0){					
						authorized.new_user = false;
						authorized.token = '';
						authorized.email = username;
						authorized.role = users[0].role;
						var payload = {email: username ,role: authorized.role };

						jwt.sign(payload,serverConfig.app_rest_jwt_secret,{},function(err_,result_){
							authorized.token = result_;	
							res.json(authorized);	
						});
					}else{
					aCreateAppLdapUser_r(username,function(created){						
							authorized.new_user = true;
							authorized.token = '';
							authorized.email = username;
							authorized.role = serverConfig.app_rest_signup_role;
							var payload = {email: username ,role: authorized.role };
							
							jwt.sign(payload,serverConfig.app_rest_jwt_secret,{},function(err__,result__){
								authorized.token= result__;	
								res.json(authorized);	
							});							
					})									
				}				
			})			
		}else{ //LDAP Auth Failed
			res.send(authResponses.invalidCredentials);
		}	
	});	
});

var aCreateAppLdapUser_r = function(username,callback){
	
	var appRequest_OPT_ = extend({},appRequest_OPT);	
	appRequest_OPT_.url = appRequest_OPT_.url + serverConfig.app_rest_create_ldap_user_url;
	appRequest_OPT_.json = {email : username};
		
	request.post(appRequest_OPT_,function(err,res,body){
		if(err){
			aCreateAppLdapUser_r(username,function(created){
				callback(created);
			});
		}else{
			callback(body);
		}	
	});
};

var aGetAppUser_r = function(username,callback){

	var appRequest_OPT_ = extend({},appRequest_OPT);
	appRequest_OPT_.url =  appRequest_OPT_.url + serverConfig.app_rest_get_ldap_users_url+'?email=eq.'+username;		
	appRequest_OPT_.json = {};
	
	request.get(appRequest_OPT_,function (err,res,body){
		if(err){
			aGetAppUser_r(username,function(users){
				callback(users)
			})
		}else{
			callback(body);
		}
	})
};

var RunServer = function(){
	var server = app.listen(8081, function () {
		var host = server.address().address;
		var port = server.address().port;
		console.log("App listening at http://%s:%s", host, port);  
	})
};

var GetAppLdapUserJwt_r = function(){	
	var appLogin_OPT_ = extend({},appLogin_OPT);

	appLogin_OPT_.json.email = serverConfig.app_dbldap_user;
	appLogin_OPT_.json.pass = serverConfig.app_dbldap_password;	
	appLogin_OPT_.url =  appLogin_OPT_.url + serverConfig.app_rest_login_url;
		
	console.log('Connecting to Application Backend...!')	

	request.post(appLogin_OPT_,function(err,res,body){
		if(err){		
			
			setTimeout(function() {
  			console.log('Failed to Connect to Application Backend, Retrying...!')
  			GetAppLdapUserJwt_r();	
			},2000);				
			
		}else{			
			console.log('Connected to Application Backend...!')			
			token = body.token;				
			appRequest_OPT.headers = { 'Authorization' : 'Bearer '+token }
			RunServer();
		}
	});

};

var aResolveServers_r = function(fqdn,callback){
	dns.lookup(fqdn,function(err,addresses,family){
		if(addresses){
			callback(addresses);	
		}
		else{
			aResolveServers_r(fqdn,function(addresses_){
				callback(addresses_);
			})
		}
	})
};

var InitializeServer = function(){
	
	console.log('Preparing to Run Server...!');
	console.log('Resolving Auxilary Servers using Host Names...!');
	console.log('Attempting to Resolve Active Directory...!');

	aResolveServers_r(serverConfig.app_ldap_host,function(result){
		console.log('Active Directory Resolved to',result,'...!');		
		console.log('Attempting to Resolve Rest Server...!');		

		adConfig.url = 'ldap://'+result;
		adConfig.baseDN = serverConfig.app_ldap_base_dn;  
		ad = new ActiveDirectory(adConfig);

		aResolveServers_r(serverConfig.app_rest_host,function(result_){
			console.log('Rest Server Resolved to',result_,'...!');		
			
			appLogin_OPT.url = 'http://'+result_+':'+serverConfig.app_rest_port;
			appRequest_OPT.url = 'http://'+result_+':'+serverConfig.app_rest_port;
			GetAppLdapUserJwt_r();
		})	
	})
};

InitializeServer();

