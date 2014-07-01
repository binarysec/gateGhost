# gateGhost ultimate anti-trackers for networks
gateGhost is a free anti-trackers proxy solution for whole network. It is based as a plugin on gatejs proxy server.

It is distributed under the GPL v3 licence with a professional support under a private commercial licence (dual licence). 

It was designed to counter industrial and individual spying currently operated and revealed by Edward Snowden case.

gateGhost also clean all the ads on your network that constantly hounding your facts and digital gestures.

The implementation of such technology in business and home networks becomes a necessity.

* Made for fat architectures
* ~1900 trackers registered in the database with fast search system
* Cookie inspection system with 100+ cookies registered
* Referer confidence system that removes unwanted referers w/o impacts on usage
* Add your own trackers & cookie database
* White list of trackers per category
* Etag session tracking hack support "tracking without cookie"

As it is open source contributions must follow the Github's workflow (issues, pull requests) 

Please contact us, If you found new sort of trackers, cookies or any other way to by-pass our system !

The professional support is managed by the BinarySEC company. Feel free to contact us info [at] binarysec [dot] com

## Installation

First you will have to install gatejs on your server. You will find some good examples and howto's on http://github.com/binarysec/gate

When gatejs is installed and gateGhost downloaded you will have :
* Add the plugin 
* Add **ghost** opcode into your favorite gatejs pipeline

### Add the plugin
gateGhost plugin is installed using **plugins** input into your gatejs configuration
```js
var serverConfig = function(bs) { return({
	// [...]
	plugins: [
		'/path/to/gateGhost'
	],
	// [...]
})};
module.exports = serverConfig;
```

### Add ghost opcode
Ghost acts as a forward proxy opcode (doesn't work on reverse proxy). 

Below an full example with **ghost** opcode into the pipeline named **pipetest**
```js
var serverConfig = function(bs) { return({
	hostname: "testServer0",
	userId: 'proxy',
	groupId: 'proxy',
	runDir: "/tmp/gatejs",
	dataDir: "/home/data",
	logDir: "/var/log/gatejs",
	confDir: '/etc/gatejs',
	
	plugins: [
		'/path/to/gateGhost'
	],
	
	http: {
		forwardInterface: {
			type: 'forward',
			port: 8080,
			pipeline: 'pipetest'
		},
	},
	
	pipeline: {
		pipetest: [
			['ghost'],
			['cache', { }],
			['proxyPass', { mode: 'host' }]
		],
	},
})};
module.exports = serverConfig;
```

## Documentations
Documentations are available on the gateGhost Wiki @ https://github.com/binarysec/gateGhost/wiki

### Ghost pipeline options

* **searchTrackers** : Activate the "search trackers" feature 
* **refererConfidence** : Activate referer confidence system in order to remove unwanted referers, default ON (true)
* **cookieInspection** : Activate cookie inspection in order to clean unwanted tracking cookies, default ON (true)
* **etagSessionHack** : Activate ETag session hack mechanism by removing etag header from responses, default ON (true)
* **dbError** : Select the method to block tracking requests, **code** will return a 403 HTTP code instead of **close** will immediately close the connection. Default **code**.
* **log** : Manage log level, you must use an object {} and folow options below
* **db** : Activate database (trackers) logging, default ON (true)
  * **referer** : Activate referer confidence system logging, default ON (true)
  * **cookie** : Activate cookie inspection logging, default ON (true)

### Full options example
```js
var serverConfig = function(bs) { return({
	//[...]
	
	pipeline: {
		pipetest: [
			['ghost',  {
				searchTrackers: true,
				refererConfidence: true,
				cookieInspection: true,
				etagSessionHack: true,
				dbError: 'code',
				log: {
					db: true,
					referer: true,
					cookie: true,
				}
			}],
			['cache', { }],
			['proxyPass', { mode: 'host' }]
		],
	},
	
	//[...]
})};
module.exports = serverConfig;
```

## Author
Michael Vergoz @ BinarySEC
