/*
 * ==============================================================
 * 						IPv4-REP (v0.1.0)
 * ==============================================================
 *
 * 	IPv4 reputation toolkit developed for use on Node.JS / IO.JS
 * 	infosec related projects
 *
 * ==============================================================
 *
 * 	License: MIT (check attached file)
 * 	Author: undertuga[at]tutanota[dot]de
 * 	GitHub: https://github.com/undertuga/ipv4-rep
 *
 * ==============================================================
 */



/*
========================
	IPv4 Reputation
	protypes holder
========================
*/
IPv4Rep = function(){};






/*
========================
	IPv4 Reputation
	SPAMHAUS REP CHECK
========================
*/

IPv4Rep.prototype.spamhaus = function(ipv4, callback){

	// validating gathered data
	if((typeof(ipv4) === 'undefined') || (ipv4 === null) || (ipv4.length <= 0)){callback(null, false); return;}
	else{

		// declaring required external libs
		var dns = require('dns'), rawIP = ipv4.split(".");

		// checking spamhaus reputation service
		dns.resolve4(rawIP[3] + '.' + rawIP[2] + '.' + rawIP[1] + '.' + rawIP[0] + '.zen.spamhaus.org',

			function(err, res){

				// fail safe bail out
				if(err || !res){callback(null, false); return;}
				else{callback(null, res); return;}
			}
		);
	}
};








/*
========================
	IPv4 Reputation
	MAILSPIKE REP CHECK
========================
*/

IPv4Rep.prototype.mailspike = function(ipv4, callback){

	// validating gathered data
	if((typeof(ipv4) === 'undefined') || (ipv4 === null) || (ipv4.length <= 0)){callback(null, false); return;}
	else{

		// declaring required external libs
		var dns = require('dns'), rawIP = ipv4.split(".");

		// checking mailspike reputation service
		dns.resolve4(rawIP[3] + '.' + rawIP[2] + '.' + rawIP[1] + '.' + rawIP[0] + '.rep.mailspike.net',

			function(err, res){

				// fail safe bail out
				if(err || !res){callback(null, false); return;}
				else{callback(null, res); return;}
			}
		);
	}
};









/*
========================
	IPv4 Reputation
	MAILSPIKE REP CHECK
========================
*/

IPv4Rep.prototype.spamcop = function(ipv4, callback){

	// validating gathered data
	if((typeof(ipv4) === 'undefined') || (ipv4 === null) || (ipv4.length <= 0)){callback(null, false); return;}
	else{

		// declaring required external libs
		var dns = require('dns'), rawIP = ipv4.split(".");

		// checking spamcop reputation service
		dns.resolve4(rawIP[3] + '.' + rawIP[2] + '.' + rawIP[1] + '.' + rawIP[0] + '.bl.spamcop.net',

			function(err, res){

				// fail safe bail out
				if(err || !res){callback(null, false); return;}
				else{callback(null, res); return;}
			}
		);
	}
};










/*
========================
	IPv4 Reputation
	SORBS REP CHECK
========================
*/

IPv4Rep.prototype.sorbs = function(ipv4, callback){

	// validating gathered data
	if((typeof(ipv4) === 'undefined') || (ipv4 === null) || (ipv4.length <= 0)){callback(null, false); return;}
	else{

		// declaring required holders
		var dns = require('dns'), rawIP = ipv4.split(".");

		// checking SORBS reputation service
		dns.resolve4(rawIP[3] + '.' + rawIP[2] + '.' + rawIP[1] + '.' + rawIP[0] + '.dnsbl.sorbs.net',

			function(err, res){

				// fail safe bail out
				if(err || !res){callback(null, false); return;}
				else{callback(null, res); return;}
			}
		);
	}
};











/*
========================
	IPv4 Reputation
	CBL REP CHECK
========================
*/

IPv4Rep.prototype.cbl = function(ipv4, callback){

	// validating gathered data
	if((typeof(ipv4) === 'undefined') || (ipv4 === null) || (ipv4.length <= 0)){callback(null, false); return;}
	else{

		// declaring required holders
		var dns = require('dns'), rawIP = ipv4.split(".");

		// checking CBL reputation service
		dns.resolve4(rawIP[3] + '.' + rawIP[2] + '.' + rawIP[1] + '.' + rawIP[0] + '.cbl.abuseat.org',

			function(err, res){

				// fail safe bail out
				if(err || !res){callback(null, false); return;}
				else{callback(null, res); return;}
			}
		);
	}
};









/*
========================
	IPv4 Reputation
	UNSUBSCORE REP CHECK
========================
*/

IPv4Rep.prototype.unsubscore = function(ipv4, callback){

	// validating gathered data
	if((typeof(ipv4) === 'undefined') || (ipv4 === null) || (ipv4.length <= 0)){callback(null, false); return;}
	else{

		// declaring required holders
		var dns = require('dns'), rawIP = ipv4.split(".");

		// checking UNSUBSCORE reputation service
		dns.resolve4(rawIP[3] + '.' + rawIP[2] + '.' + rawIP[1] + '.' + rawIP[0] + '.ubl.unsubscore.com',

			function(err, res){

				// fail safe bail out
				if(err || !res){callback(null, false); return;}
				else{callback(null, res); return;}
			}
		);
	}
};







// exporting prototypes
exports.IPv4Rep = IPv4Rep;
