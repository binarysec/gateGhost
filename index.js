/*
 * Copyright (c) 2010-2014 BinarySEC SAS
 * gatejs plugin interface [http://www.binarysec.com]
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

var cluster = require('cluster');
var url = require('url');

var gateGhost = function(gjs) { };

gateGhost.db = require(__dirname+'/js/db.js');

/* used to instance object as lib */
gateGhost.getName = function() { return('gateGhost'); }

gateGhost.dbLog = function(pipe, rule) {
	gateGhost.gjs.lib.core.logger.commonLogger(
		'GhostDbLog',
		{
			request: pipe.request.urlParse,
			ip: pipe.request.remoteAddress,
			method: pipe.request.method,
			userAgent: pipe.request.headers['user-agent'] ? pipe.request.headers['user-agent'] : '-',
			referer: pipe.request.headers.referer ? pipe.request.headers.referer : '-',
			rule: rule
		}
	);
}

gateGhost.refererLog = function(pipe) {
	gateGhost.gjs.lib.core.logger.commonLogger(
		'GhostRefererLog',
		{
			request: pipe.request.urlParse,
			ip: pipe.request.remoteAddress,
			method: pipe.request.method,
			userAgent: pipe.request.headers['user-agent'] ? pipe.request.headers['user-agent'] : '-',
			referer: pipe.request.headers.referer ? pipe.request.headers.referer : '-',
		}
	);
}

gateGhost.cookieLog = function(pipe, detection) {
	gateGhost.gjs.lib.core.logger.commonLogger(
		'GhostCookieLog',
		{
			request: pipe.request.urlParse,
			ip: pipe.request.remoteAddress,
			method: pipe.request.method,
			userAgent: pipe.request.headers['user-agent'] ? pipe.request.headers['user-agent'] : '-',
			referer: pipe.request.headers.referer ? pipe.request.headers.referer : '-',
			detection: detection
		}
	);
}

gateGhost.loader = function(gjs) {
	gateGhost.gjs = gjs;
	
	if (cluster.isMaster) {
		var logger = gjs.lib.core.logger;
		
		/* create logging receiver */
		var processDbLog = function(req) {
			var dateStr = gjs.lib.core.dateToStr(req.msg.time);
			var u = url.format(req.msg.request);
			
			var info = '';
			if(req.msg.rule.name)
				info += '"'+req.msg.rule.name+'"';
			if(req.msg.rule.category) {
				info += ' '+req.msg.rule.category.toLowerCase()+' ';
			}
			else
				info += ' ';
			
			var inline = 
				dateStr+' '+
				req.msg.ip+' '+
				info+
				req.msg.method+' '+
				u+' '+
				'"'+req.msg.userAgent+'" '+
				req.msg.referer
			;
			
			/* write log */
			var f = logger.selectFile(req.msg.site, 'gateGhost-trackers');
			if(f) 
				f.stream.write(inline+'\n');
		}

		var processRefererLog = function(req) {
			var dateStr = gjs.lib.core.dateToStr(req.msg.time);
			var u = url.format(req.msg.request);
			
			var inline = 
				dateStr+' '+
				req.msg.ip+' '+
				req.msg.method+' '+
				u+' '+
				'"'+req.msg.userAgent+'" '+
				req.msg.referer
			;
			
			/* write log */
			var f = logger.selectFile(req.msg.site, 'gateGhost-referer');
			if(f) 
				f.stream.write(inline+'\n');
		}
		
		var processCookieLog = function(req) {
			var dateStr = gjs.lib.core.dateToStr(req.msg.time);
			var u = url.format(req.msg.request);
			
			var info = '';
			var first = true;
			for(var a in req.msg.detection) {
				if(first == false)
					info += ',';
				info += req.msg.detection[a].pattern;
				
				first = false;
			}
			
			var inline = 
				dateStr+' '+
				req.msg.ip+' cookies '+
				info+' removed '+
				req.msg.method+' '+
				u+' '+
				'"'+req.msg.userAgent+'" '+
				req.msg.referer
			;
	
			/* write log */
			var f = logger.selectFile(req.msg.site, 'gateGhost-cookies');
			if(f) 
				f.stream.write(inline+'\n');
		}
		
		logger.typeTab['GhostDbLog'] = processDbLog;
		logger.typeTab['GhostRefererLog'] = processRefererLog;
		logger.typeTab['GhostCookieLog'] = processCookieLog;
		return;
	}
	
	gateGhost.db.loader(gjs);
    
	/* load opcodes */
	gjs.lib.core.pipeline.scanOpcodes(
		__dirname+'/pipeForward',
		'forwarding'
	);

}

module.exports = gateGhost;