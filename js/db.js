/*
 * Copyright (c) 2010-2014 BinarySEC SAS
 * Database manager [http://www.binarysec.com]
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

var fs = require('fs');
var db = function(gjs) { 
	db.loaded = false;
};

db.categories = {};
db.stats = {
	rules: 0,
	regexHostRules: 0,
	regexURIRules: 0,
	regexRules: 0,
	nregHostRules: 0,
	nregURIRules: 0,
	nregRules: 0,
	categories: 0
}


db.searchTrackers = function(url) {
	var pos;
	
	/* nreg host */
	pos = db.nregHost.match(db.gjs.lib.core.utils.cstrrev(url.hostname));
	if(pos)
		return(db.globalTrackers[pos]);
	
	/* nreg URI */
	pos = db.nregURI.match(url.hostname+url.path);
	if(pos)
		return(db.globalTrackers[pos]);
	
	/* try regex on host */
	var regex = new RegExp;
	for(var a in db.regexHost) {
		pos = db.regexHost[a];
		regex.compile(pos);
		if(regex.test(url.hostname))
			return(db.globalTrackers[pos]);
	}
	
	/* try regex on URI */
	for(var a in db.regexURI) {
		pos = db.regexURI[a];
		regex.compile(pos);
		if(regex.test(url.hostname+url.path))
			return(db.globalTrackers[pos]);
	}	
	
	return(false);
}



db.searchCookie = function(key) {
	/* search using nreg */
	pos = db.nregCookie.match(key);
	if(pos)
		return(db.globalCookie[key]);
	
	return(false);
	
}

db.loader = function(gjs) {
	db.gjs = gjs; 
	db.globalTrackers = {};
	db.nregHost = new gjs.lib.core.nreg;
	db.nregURI = new gjs.lib.core.nreg;
	db.regexHost = [];
	db.regexURI = [];
	
	db.globalCookie = {};
	db.nregCookie = new gjs.lib.core.nreg;
	db.regexCookie = [];
	
	function processTrackers(line) {
		var item = line.split('#');
		
		if(item.length <= 1)
			return;
		
		var pdata = {
			reference: item[0],
			active: item[1] == 'true' ? true:false,
			category: item[2],
			name: item[3],
			type: item[4],
			pattern: item[5],
		}
	
		switch(pdata.type) {
			case 'nreghost':
				pdata.pattern = gjs.lib.core.cstrrev(pdata.pattern);
				db.nregHost.add(pdata.pattern);
				db.stats.nregHostRules++;
				break;
			case 'nreguri':
				db.nregURI.add(pdata.pattern);
				db.stats.nregURIRules++;
				break;
			case 'regexhost':
				db.regexHost.push(pdata.pattern);
				db.stats.regexHostRules++;
				break;
			case 'regexuri':
				db.regexURI.push(pdata.pattern);
				db.stats.regexURIRules++;
				break;
		}
		
		db.globalTrackers[pdata.pattern] = pdata;
		
		db.stats.rules++;
			
	}
	
	function processCookies(line) {
		var item = line.split('#');
		
		if(item.length != 5)
			return;
		
		var pdata = {
			reference: item[0],
			active: item[1] == 'true' ? true:false,
			name: item[2],
			type: item[3],
			pattern: item[4],
		}
		
		switch(pdata.type) {
			case 'regex':
				db.regexCookie.push(pdata.pattern);
				break;
			case 'nreg':
				db.nregCookie.add(pdata.pattern);
				break;
		}
		
		db.globalCookie[pdata.pattern] = pdata;

	}
	
	
	function loadFile(filename, callback) {
		var data = fs.readFileSync(filename).toString();
		var lines = data.split('\n');
		for(var a in lines)
			callback(lines[a]);
	}
	
	
	loadFile(__dirname+'/trackers1.csv', processTrackers);
	loadFile(__dirname+'/trackers2.csv', processTrackers);
	loadFile(__dirname+'/cookies.csv', processCookies);
	
	db.nregURI.reload();
	db.nregHost.reload();
	
	db.nregCookie.reload();
	
	db.loaded = true;
}

module.exports = db;