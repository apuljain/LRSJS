//@Author: Apul Jain, apul@iitg.ernet.in
//Date: 5th Aug 2012

var assert = require('assert')
  , dsa = require('./library/dsa.js')
  
if(process.argv.length != 3)
{
	console.log("Usage: node [filename] [number of keys]");
	process.exit(1);
}

var num_keys = process.argv[2];
var i = 0;

var base_key = new dsa.Key();

var fs = require('fs');

while(i++ < num_keys)
{
	var new_key = new dsa.Key(base_key.p, base_key.q, base_key.g);
	var public_key = new_key.packPublic();	
	var private_key = new_key.packPrivate();

	var file_path_public = "./public/pubkey" + i;
	var file_path_priv = "./private/privkey" + i;
	
	fs.writeFile(file_path_public, JSON.stringify(public_key), 'binary',
	 function (err) {
	  if (err) throw err;
	  console.log("success");
	});
	
	fs.writeFile(file_path_priv, JSON.stringify(private_key), 'binary',
	 function (err) {
	  if (err) throw err;
	  console.log("success");
	});
}
