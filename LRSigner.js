//@Author: Apul Jain, apul@iitg.ernet.in
//Date: 5th Aug 2012

var assert = require('assert')
  , hlp = require('./library/helpers.js')
  , dsa = require('./library/dsa.js')
  , BigInt = require('./library/bigint.js')
  , lrsignature = require('./LRSignature.js')
  
//pass array of public_keys objects, a private_key object and the context_tag
//Note: Here priv_key is the DSA.Key() object which gives access 
//to group parameters, public_key ('y') and the private key('x')
//Refer dsa.js for DSA.Key properties.Each public_keys vector object has to
//be parsed by DSA.parsePublic() function to get 'y' and other group params.

function LRSigner (public_keys, priv_key, context_tag) {
	
	var _public_keys  = new Array(public_keys.length);

	//get publickeys 'y' vector 
	for(i=0; i<public_keys.length; i++)
	  _public_keys[i] = (public_keys[i]).y;
	
	var _priv_key = priv_key.x;
	var _self_public_key = priv_key.y;
	var _context_tag = context_tag;
		
	var _g = priv_key.g;
	var _p = priv_key.p;
	var _q = priv_key.q;
	
	var _num_members = _public_keys.length;
	var _self_identity = (function() {
	  for(i=0; i<_public_keys.length; i++)
	  {
		 if( BigInt.equals(_public_keys[i], _self_public_key))
			return i;
	  }
	  console.log("InValid private key");
		return -1;
	  })();
	
	this.LRSign = function LRSign(message) {
		
		var _message = message;
		//prepare input vector for group hash - [public keys] + context_tag
		var input_array = [].concat(_public_keys);
		input_array.push(_context_tag);
		
		var group_hash = BigInt.mod(
		  BigInt.str2bigInt(hlp.ComputeVectorHash(input_array, _q), 16), _q);
		
		//map group_hash to an element of the group
		group_hash = BigInt.powMod(_g, group_hash, _p);
		var _linkage_tag = BigInt.powMod(group_hash, _priv_key, _p);
		
		//get randBigInt in range {0...q-1}
		var u = BigInt.mod(BigInt.randBigInt(BigInt.bitSize(_q), 1), _q);
		
		//declare commitment and signatures variable
		var commit = new Array(_num_members), signs = new Array(_num_members);
				
		//initial commitment
		input_array = [].concat(_public_keys);
		input_array.push(_linkage_tag);
		input_array.push(_message);
		
		var common_array = [].concat(input_array);

		input_array.push(BigInt.powMod(_g, u, _p));
		input_array.push(BigInt.powMod(group_hash, u, _p)); 
		
		commit[(_self_identity+1)%_num_members] = BigInt.str2bigInt(
		  hlp.ComputeVectorHash(input_array, _q), 16);
		
		for(i = (_self_identity+1)%_num_members; i != _self_identity;
		  i = (i+1)%_num_members)
		{
			_signs_i = BigInt.mod(BigInt.randBigInt(BigInt.bitSize(_q), 1), _q);
		    
		    //pack into MPI for portability across platforms.
		    //This will be used as signature component.
		    signs[i] = hlp.packMPI(_signs_i);
		    		
			input_array = [].concat(common_array);
			input_array.push(BigInt.multMod(
				BigInt.powMod(_g, _signs_i, _p), BigInt.powMod(_public_keys[i],
			    commit[i], _p), _p));
			
			input_array.push(BigInt.multMod(
				BigInt.powMod(group_hash, _signs_i, _p),
				BigInt.powMod(_linkage_tag, commit[i], _p), _p));
			
			commit[(i+1)%_num_members] = BigInt.str2bigInt(
			  hlp.ComputeVectorHash(input_array, _q), 16);
		}

		signs[_self_identity] = hlp.packMPI(hlp.subMod(
		  u, BigInt.multMod(_priv_key, commit[_self_identity], _q), _q));
		
		//converting signature components into MPI
		//create LRSignature object
		var final_signature = new lrsignature.LRSignature(
		  hlp.packMPI(commit[0]), signs, hlp.packMPI(_linkage_tag));
		  
		return final_signature;
	}	
}

module.exports = {
	LRSigner : LRSigner
}
