/*
 * Copyright (c) 2010-2014 BinarySEC SAS
 * Ghost opcode [http://www.binarysec.com]
 * 
 * This file is part of gateGhost
 * 
 * Gate.js is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Origin: Michael VERGOZ
 */

var url = require('url');

var ghost = function(gjs) { }

function estimateConfidence(host) {
	return(ghost.gjs.lib.core.cstrrev(host).split('.').slice(0, 2).join(''));
}

function parseCookie(str) {
	var obj = {}
	var pairs = str.split(/; */);
	pairs.forEach(function(pair) {
		var eq_idx = pair.indexOf('=')
		if(eq_idx < 0)
			return;
		var key = pair.substr(0, eq_idx).trim()
		var val = pair.substr(++eq_idx, pair.length).trim();
		if(val[0] == '"')
			val = val.slice(1, -1);
		if(obj[key] == undefined) {
			try {
				obj[key] = decodeURIComponent(val);
			} catch (e) {
				obj[key] = val;
			}
		}
	});
	return(obj);
};

ghost.request = function(pipe, options) {
	if(options === undefined)
		options = {};
	
	/* defaulting options */
	var searchTrackers = true;
	if(options.searchTrackers == false)
		searchTrackers = false;
	
	var refererConfidence = true;
	if(options.refererConfidence == false)
		refererConfidence = false;
	
	var dbError = 'code';
	if(options.dbError == 'close')
		dbError = 'close';
	
	var cookieInspection = true;
	if(options.cookieInspection == false)
		cookieInspection = false;
	
	var etagSessionHack = true;
	if(options.etagSessionHack == false)
		etagSessionHack = false;
	
	/* defaulting log */
	var log = {
		db: true,
		referer: true,
		cookie: true
	};
	if(options.log) {
		for(var a in options.log) {
			var b = options.log[a];
			if(log[a] && b == false)
				log[a] = false;
		}
	}
	
	/* fix hostname */
	if(!pipe.request.urlParse.hostname)
		pipe.request.urlParse.hostname = pipe.request.headers.host;
	
	/* process link pattern database */
	if(searchTrackers == true) {
		var result = pipe.root.lib.gateGhost.db.searchTrackers(pipe.request.urlParse);
		if(result && result.active == true) {
			
			if(log.db == true)
				pipe.root.lib.gateGhost.dbLog(pipe, result);

			if(dbError == 'close') {
				pipe.stop();
				pipe.response.destroy();
				return(true);
			}
			
			pipe.stop();
			pipe.response.writeHead(403, {
				Server: 'gatejs',
				Pragma: 'no-cache',
				Information: 'Your request has been blocked by gatejs',
				Connection: 'close'
			});
			pipe.response.end();
			return(true);
		}
	}
	
	/* process referer inspection */
	if(refererConfidence == true && pipe.request.headers.referer) {
		var up = url.parse(pipe.request.headers.referer),
		reqRC = estimateConfidence(pipe.request.headers.host),
		refRC = estimateConfidence(up.host);
		if(reqRC != refRC) {
			if(log.referer == true)
				pipe.root.lib.gateGhost.refererLog(pipe);
			pipe.request.gjsRemoveHeader('Referer');
		}
	}

	/* operate on cookie */
	var cookieChange = false;
	if(cookieInspection == true && pipe.request.headers.cookie !== undefined) {
		var detection = [];
		var recooked = parseCookie(pipe.request.headers.cookie);
		for(var a in recooked) {
			var r = pipe.root.lib.gateGhost.db.searchCookie(a); 
			if(r && r.active == true) {
				delete recooked[a];
				cookieChange = true;
				detection.push(r);
			}
		}
		
		if(cookieChange) {
			if(log.cookie == true)
				pipe.root.lib.gateGhost.cookieLog(pipe, detection);
		}
	}
	
	/* rebuild if necessary */
	if(cookieChange == true) {
		pipe.request.headers.cookie = '';
		for(var a in recooked)
			pipe.request.headers.cookie += a+'='+encodeURIComponent(recooked[a])+'; ';
	}

	/* 
	 * operate on ETag tracker hack 
	 * because ETag isn't really useful for caching objects we decide 
	 * to remove them from the response
	 * It doesn't really affect cache engine
	 * Most Useless Stuff (c)
	 */
	if(etagSessionHack == true) {
		pipe.response.on("response", function(res, type) {
			if(res.headers.etag) 
				delete res.gjsRemoveHeader('etag');
		});
	}
	
}

ghost.ctor = function(gjs) {
	ghost.gjs = gjs;
}

module.exports = ghost;


