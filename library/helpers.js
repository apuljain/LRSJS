//Adapted from https://github.com/arlolra/otr/blob/master/helpers.js with some changes.
;(function () {

  var root = this

  var HLP
  if (typeof exports !== 'undefined') {
    HLP = exports
  } else {
    HLP = root.HLP = {}
  }

  var BigInt = root.BigInt
    , SHA256 = root.SHA256

  if (typeof require !== 'undefined') {
    BigInt || (BigInt = require('./bigint.js'))
    SHA256 || (SHA256 = require('./sha256.js'))
  }

  HLP.divMod = function divMod(num, den, n) {
    return BigInt.multMod(num, BigInt.inverseMod(den, n), n)
  }

  HLP.subMod = function subMod(one, two, n) {
    one = BigInt.mod(one, n)
    two = BigInt.mod(two, n)
    if (BigInt.greater(two, one)) one = BigInt.add(one, n)
    return BigInt.sub(one, two)
  }

  HLP.randomExponent = function randomExponent() {
    return BigInt.randBigInt(1536)
  }

  HLP.randomValue = function randomValue() {
    return BigInt.randBigInt(128)
  }

  HLP.smpHash = function smpHash(version, fmpi, smpi) {
    var sha256 = SHA256.algo.SHA256.create()
    sha256.update(version.toString())
    sha256.update(BigInt.bigInt2str(fmpi, 10))
    if (smpi) sha256.update(BigInt.bigInt2str(smpi, 10))
    var hash = sha256.finalize()
    return BigInt.str2bigInt(hash.toString(SHA256.enc.Hex), 16)
  }

  HLP.multPowMod = function multPowMod(a, b, c, d, e) {
    return BigInt.multMod(BigInt.powMod(a, b, e), BigInt.powMod(c, d, e), e)
  }

  HLP.ZKP = function ZKP(v, c, d, e) {
    return BigInt.equals(c, HLP.smpHash(v, d, e))
  }

  // greater than, or equal
  HLP.GTOE = function GTOE(a, b) {
    return (BigInt.equals(a, b) || BigInt.greater(a, b))
  }

  HLP.between = function between(x, a, b) {
    return (BigInt.greater(x, a) && BigInt.greater(b, x))
  }

  var OPS = {
      'XOR': function (c, s) { return c ^ s }
    , 'OR': function (c, s) { return c | s }
    , 'AND': function (c, s) { return c & s }
  }
  HLP.bigBitWise = function bigBitWise(op, a, b) {
    var tf = (a.length > b.length)
    var short = tf ? b : a
    var c = BigInt.dup(tf ? a : b)
    var i = 0, len = short.length
    for (; i < len; i++) {
      c[i] = OPS[op](c[i], short[i])
    }
    return c
  }

  HLP.CalculateHash = function CalculateHash(input) {
     var sha256 = SHA256.algo.SHA256.create()
     sha256.update(input)
     return sha256.finalize().toString()
  }

  //pass input array of bigInts and it will return hash value mod q
  HLP.ComputeVectorHash = function ComputeVectorHash(input, q) {
    var sha256 =  SHA256.algo.SHA256.create()
    for(i = 0; i < input.length; i++)
    {
    	if(typeof(input[i]) == String)
    		sha256.update(input[i]);
    	else
	        sha256.update(BigInt.bigInt2str(input[i], 16));
    }
    
    var value = BigInt.mod(BigInt.str2bigInt(sha256.finalize().toString(), 16), q);
      
    return BigInt.bigInt2str(value, 16);
  }

  HLP.h2 = function h2(b, secbytes) {
    var sha256 = SHA256.algo.SHA256.create()
    sha256.update(b)
    sha256.update(secbytes)
    var hash = sha256.finalize()
    return hash.toString(SHA256.enc.Latin1)
  }

  HLP.mask = function mask(bytes, start, n) {
    start = start / 8
    return bytes.substring(start + 0, start + (n / 8))
  }

  HLP.twotothe = function twotothe(g) {
    var ex = g % 4
    g = Math.floor(g / 4)
    var str = (Math.pow(2, ex)).toString()
    for (var i = 0; i < g; i++) str += '0'
    return BigInt.str2bigInt(str, 16)
  }

  HLP.pack = function pack(d) {
    // big-endian, unsigned long
    var res = ''
    res += _toString(d >> 24 & 0xFF)
    res += _toString(d >> 16 & 0xFF)
    res += _toString(d >> 8 & 0xFF)
    res += _toString(d & 0xFF)
    return res
  }

  HLP.packData = function packData(d) {
    return HLP.pack(d.length) + d
  }

  HLP.unpackData = function unpackData(d) {
    return d.substring(4)
  }

  HLP.bigInt2bits = function bitInt2bits(bi) {
    bi = BigInt.dup(bi)
    var ba = ''
    while (!BigInt.isZero(bi)) {
      ba = _num2bin[bi[0] & 0xff] + ba
      BigInt.rightShift_(bi, 8)
    }
    return ba
  }

  HLP.packMPI = function packMPI(mpi) {
    return HLP.packData(HLP.bigInt2bits(BigInt.trim(mpi, 0)))
  }

  HLP.readData = function readData(data) {
    var n = (data.splice(0, 4)).reduce(function (p, n) {
      p <<= 8; return p | n
    }, 0)
    return [n, data]
  }

  HLP.retMPI = function retMPI(data) {
    var mpi = BigInt.str2bigInt('0', 10, data.length)
    data.forEach(function (d, i) {
      if (i) BigInt.leftShift_(mpi, 8)
      mpi[0] |= d
    })
    return mpi
  }

  HLP.readMPI = function readMPI(data) {
    data = HLP.toByteArray(data)
    data = HLP.readData(data)
    return HLP.retMPI(data[1])
  }

  HLP.parseStr = function parseStr(str) {
    var s = []
    str = HLP.toByteArray(str)
    while (str.length) {
      str = HLP.readData(str)
      s.push(str[1].splice(0, str[0]))
      str = str[1]
    }
    return s
  }

  HLP.parseToStrs = function parseToStrs(str) {
    var n, s = []
    while (str.length) {
      n = (HLP.readData(HLP.toByteArray(str.substring(0, 4))))[0] + 4
      s.push(str.substring(0, n))
      str = str.substring(n)
    }
    return s
  }

  // https://github.com/msgpack/msgpack-javascript/blob/master/msgpack.js

  var _bin2num = {}
    , _num2bin = {}
    , _toString = String.fromCharCode
    , _num2b64 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                  "abcdefghijklmnopqrstuvwxyz0123456789+/").split("")
    , globalScope = this  // meh

  var i = 0, v
  for (; i < 0x100; ++i) {
    v = _toString(i)
    _bin2num[v] = i  // "\00" -> 0x00
    _num2bin[i] = v  //     0 -> "\00"
  }
  for (i = 0x80; i < 0x100; ++i) {  // [Webkit][Gecko]
    _bin2num[_toString(0xf700 + i)] = i  // "\f780" -> 0x80
  }

  HLP.toByteArray = function toByteArray(data) {
    var rv = [], bin2num = _bin2num, remain
      , ary = data.split("")
      , i = -1
      , iz

    iz = ary.length
    remain = iz % 8

    while (remain--) {
      ++i
      rv[i] = bin2num[ary[i]]
    }
    remain = iz >> 3
    while (remain--) {
      rv.push(bin2num[ary[++i]], bin2num[ary[++i]],
              bin2num[ary[++i]], bin2num[ary[++i]],
              bin2num[ary[++i]], bin2num[ary[++i]],
              bin2num[ary[++i]], bin2num[ary[++i]])
    }
    return rv
  }

  HLP.base64encode = function base64encode(data) {
    var rv = []
      , c = 0, i = -1, iz = data.length
      , pad = [0, 2, 1][data.length % 3]
      , num2bin = _num2bin
      , num2b64 = _num2b64

    if (globalScope.btoa) {
      while (i < iz) {
        rv.push(num2bin[data[++i]])
      }
      return btoa(rv.join(""))
    }
    --iz
    while (i < iz) {
      c = (data[++i] << 16) | (data[++i] << 8) | (data[++i])  // 24bit
      rv.push(num2b64[(c >> 18) & 0x3f],
              num2b64[(c >> 12) & 0x3f],
              num2b64[(c >>  6) & 0x3f],
              num2b64[ c        & 0x3f])
    }
    pad > 1 && (rv[rv.length - 2] = "=")
    pad > 0 && (rv[rv.length - 1] = "=")
    return rv.join("")
  }

}).call(this)