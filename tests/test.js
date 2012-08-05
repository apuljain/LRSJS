//@Author: Apul Jain, apul@iitg.ernet.in
//Date: 5th Aug 2012

var assert = require('assert')
  , dsa = require('../library/dsa.js')
  , lrsigner = require('../LRSigner.js')
  , lrverifier = require('../LRVerifier.js')

var fs = require('fs');

var file_path_public = "../public/";
var file_path_priv = "../private/";

var public_keys = [];
var private_keys = [];

var file_names_public = fs.readdirSync(file_path_public);
var file_names_priv = fs.readdirSync(file_path_priv);

var i = 0;
while(i<file_names_public.length)
{	
	var data = fs.readFileSync((file_path_public + file_names_public[i]),
	 'binary');
 	public_keys.push(dsa.parsePublic(JSON.parse(String(data))));
	
	var data1 = fs.readFileSync((file_path_priv + file_names_priv[i]),
	 'binary');
	private_keys.push(dsa.parsePrivate(JSON.parse(String(data1))));
    i++;
}

//create prover-verifier objects.
var context_tag = "Tag";
var msg = "Hello";

var prover = new lrsigner.LRSigner(public_keys, private_keys[0], context_tag);

var signature = prover.LRSign(msg);
var verifier = new lrverifier.LRVerifier(public_keys, context_tag);

//Check for Success test cases.
assert.equal(1, verifier.LRVerify(msg, signature),
 "Signature Verification Successful!");

//Check for Failure test cases.
public_keys[0] = public_keys[1]; 
var verifier = new lrverifier.LRVerifier(public_keys, context_tag);
assert.equal(0, verifier.LRVerify(msg, signature),
 "Signature Verification Failure!");