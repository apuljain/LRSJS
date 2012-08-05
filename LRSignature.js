//define signature
function LRSignature(commit1, signatures, linkage_tag) {

    var _commit1 = commit1;
    var _linkage_tag = linkage_tag;
    var _valid = false;
    var _signatures = [].concat(signatures);
   	
	this.GetTag = function GetTag () {
		return _linkage_tag;
	}
	
	this.GetIndexSignature = function GetIndexSignature(index) {
		return _signatures[index];
	}
	
	this.GetSignatures = function GetSignatures() {
		return _signatures;
	}
	this.GetCommit1 = function GetCommit1() {
		return _commit1;
	}
	
	this.IsValid = function IsValid() {
		return _valid;
	}
}

module.exports = {
	LRSignature	: LRSignature
}
