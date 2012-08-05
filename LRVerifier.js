//@Author: Apul Jain, apul@iitg.ernet.in
//Date: 5th Aug 2012

var assert = require('assert')
  , hlp = require('./library/helpers.js')
  , dsa = require('./library/dsa.js')
  , BigInt = require('./library/bigint.js')
  , LRSign = require('./LRSignature.js')
  
//pass array of public_keys and the context_tag
//Note: Here priv_key is the DSA.Key() object which gives access 
//to group parameters, public_key ('y') and the private key('x')
//Refer dsa.js for DSA.Key properties.
function LRVerifier (public_keys, context_tag) {
	
	var _public_keys = new Array(public_keys.length);
	
	//get publickeys - 'y' - vector 
	for(i=0; i<public_keys.length; i++)
	  	_public_keys[i] = (public_keys[i]).y;
	
	var _context_tag = context_tag;
	var temp_public_key = public_keys[0]; 
	var _g = temp_public_key.g;
	var _p = temp_public_key.p;
	var _q = temp_public_key.q;
	var _num_members = _public_keys.length;

	this.LRVerify = function LRVerify(message, signature) {
		
		var _message = message;
		
		//prepare input vector for group hash - [public keys] + context_tag
		var input_array = [].concat(_public_keys);
		input_array.push(_context_tag);

		//map group_hash to an element of the group
		var group_hash = BigInt.mod(BigInt.str2bigInt(
		  hlp.ComputeVectorHash(input_array, _q), 16), _q);
		group_hash = BigInt.powMod(_g, group_hash, _p);
		 
		var commit1 = hlp.readMPI(signature.GetCommit1());
		var signs = signature.GetSignatures();
		var linkage_tag = hlp.readMPI(signature.GetTag());
	    
	    var common_array = [].concat(_public_keys);
	    common_array.push(linkage_tag);
		common_array.push(_message);
		
		for(i=0; i<_num_members; i++)
	    {
	    	var zi = BigInt.multMod(
	    	  BigInt.powMod(_g, hlp.readMPI(signs[i]), _p),
	    	  BigInt.powMod(_public_keys[i], commit1, _p), _p);
	    	 
	    	var zi_dash = BigInt.multMod(
	    	  BigInt.powMod(group_hash, hlp.readMPI(signs[i]), _p),
	    	  BigInt.powMod(linkage_tag, commit1, _p), _p);
	    	
	    	input_array = [].concat(common_array);
	    	input_array.push(zi);
	    	input_array.push(zi_dash);
			
	    	commit1 = BigInt.str2bigInt(hlp.ComputeVectorHash(input_array, _q),
	    	 16);
	     }
	 
	   	 return BigInt.equals(commit1, hlp.readMPI(signature.GetCommit1()));
	}	
}

module.exports = {
	LRVerifier : LRVerifier
}
