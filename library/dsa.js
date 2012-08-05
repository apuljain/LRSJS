// DSA
// http://www.itl.nist.gov/fipspubs/fip186.htm
//Adapted from https://github.com/arlolra/otr/blob/master/dsa.js with minor changes.

;(function () {

  var root = this

  var DSA
  if (typeof exports !== 'undefined') {
    DSA = exports
  } else {
    DSA = root.DSA = {}
  }

  var BigInt = root.BigInt
    , SHA1 = root.SHA1
    , hlp = root.hlp

  if (typeof require !== 'undefined') {
    BigInt || (BigInt = require('./bigint.js'))
    SHA1 || (SHA1 = require('./sha1.js'))
    hlp || (hlp = require('./helpers.js'))
  }

  var ZERO = BigInt.str2bigInt('0', 10)
    , ONE = BigInt.str2bigInt('1', 10)
    , TWO = BigInt.str2bigInt('2', 10)

  function makeRandom(min, max) {
    var c = BigInt.randBigInt(BigInt.bitSize(max))
    if (!hlp.between(c, min, max)) return makeRandom(min, max)
    return c
  }

  function pickBase(prime) {
    var b = BigInt.bitSize(prime)
    var base = BigInt.randBigInt(b)
    while (!BigInt.greater(prime, base))  // pick a random that's < ans
      base = BigInt.randBigInt(b)
    return base
  }

  function MR(prime) {
    var j = 0, k = true
    // 40x should give 2^-80 confidence
    for (; j < 40; j++) {
      if (!BigInt.millerRabin(prime, pickBase(prime))) {
        k = false
        break
      }
    }
    return k
  }

  DSA.Key = Key

  //constructor to generate DSA key.
  //pass group parameters to generate keys with same group parameters.
  function Key(prime, subgroup, generator) {

    if (!(this instanceof Key)) return new Key()

    this.N = 160
    this.L = 1024

    if(typeof(prime) == 'undefined' && typeof(subgroup) == 'undefined' && typeof(generator) == 'undefined')
	{
    	this.makePQ()
    	this.makeG()
	}

	else
	{
   		this.p = prime 
   		this.q = subgroup
   		this.g = generator
	}
	
    this.x = makeRandom(ZERO, this.q)
    this.y = BigInt.powMod(this.g, this.x, this.p)
  }

  Key.prototype = {

    constructor: Key,

    makePQ: function() {
      var g = this.N
      this.seed = BigInt.randBigInt(this.N)

      var u = (SHA1.SHA1(hlp.bigInt2bits(this.seed))).toString(SHA1.enc.Hex)
      var tmp = BigInt.mod(BigInt.add(this.seed, ONE), hlp.twotothe(g))
      tmp = (SHA1.SHA1(hlp.bigInt2bits(tmp))).toString(SHA1.enc.Hex)
      u = hlp.bigBitWise(
          'XOR'
        , BigInt.str2bigInt(tmp, 16)
        , BigInt.str2bigInt(u, 16)
      )

      this.q = hlp.bigBitWise('OR', u, hlp.twotothe(g - 1))
      this.q = hlp.bigBitWise('OR', this.q, ONE)

      if (!MR(this.q)) return this.makePQ()

      this.counter = 0

      var n = Math.floor(this.L / this.N)
      var b = (this.L % this.N) - 1

      // var start = new Date()
      this.step7(TWO, this.N, n, b)
      // console.log(new Date() - start)
    },

    step7: function (offset, g, n, b) {
      var V = ZERO
      var W = ZERO

      var cache_seed_plus_offset = BigInt.add(this.seed, offset)

      var i = 0
      for (; i < (n + 1); i++) {
        V = BigInt.add(
            cache_seed_plus_offset
          , BigInt.str2bigInt(i.toString(), 10)
        )
        V = SHA1.SHA1(hlp.bigInt2bits(BigInt.mod(V, hlp.twotothe(g))))
        V = BigInt.str2bigInt(V.toString(SHA1.enc.Hex), 16)
        if (i === n) V = BigInt.mod(V, hlp.twotothe(b))
        V = BigInt.mult(V, hlp.twotothe(g * i))
        W = BigInt.add(W, V)
      }

      var Lminus = hlp.twotothe(this.L - 1)
      var X = BigInt.add(W, Lminus)
      // console.log(hlp.between(X, Lminus, hlp.twotothe(this.L)))

      var c = BigInt.mod(X, BigInt.mult(TWO, this.q))
      this.p = BigInt.sub(X, BigInt.sub(c, ONE))

      if (!BigInt.greater(Lminus, this.p)) {
        // test the primality of p
        if (MR(this.p)) return
      }

      offset = BigInt.add(offset, BigInt.str2bigInt((n + 1).toString(), 10))
      this.counter += 1

      if (this.counter >= 4096) return this.makePQ()
      this.step7(offset, g, n, b)
    },

    makeG: function (e) {
      var p_minus = BigInt.sub(this.p, ONE)
      if (!e) e = BigInt.multMod(
          p_minus
        , BigInt.inverseMod(this.q, this.p)
        , this.p
      )
      var h = TWO  // makeRandom(ONE, p_minus)
      this.g = BigInt.powMod(h, e, this.p)
      if (!BigInt.greater(this.g, ONE)) this.makeG(e)
    },

	//@edit - AJ
	packPrivate: function() {
	  var str = '\x00\x00'
      str += hlp.packMPI(this.p)
      str += hlp.packMPI(this.q)
      str += hlp.packMPI(this.g)
      str += hlp.packMPI(this.x)
      str += hlp.packMPI(this.y)
      return hlp.packData(str)
	},
	
    packPublic: function () {
      var str = '\x00\x00'
      str += hlp.packMPI(this.p)
      str += hlp.packMPI(this.q)
      str += hlp.packMPI(this.g)
      str += hlp.packMPI(this.y)
      return hlp.packData(str)
    },

    hsign: function (hm) {
      var k = makeRandom(ZERO, this.q)
      var r = BigInt.mod(BigInt.powMod(this.g, k, this.p), this.q)
      if (BigInt.isZero(r)) return this.hsign(hm)
      var s = BigInt.inverseMod(k, this.q)
      s = BigInt.mult(s, BigInt.add(hm, BigInt.mult(this.x, r)))
      s = BigInt.mod(s, this.q)
      if (BigInt.isZero(s)) return this.hsign(hm)
      return [r, s]
    },

    sign: function (m) {
      var hm = SHA1.SHA1(m)
      hm = BigInt.str2bigInt(hm.toString(SHA1.enc.Hex), 16)
      return this.hsign(hm)
    }

  }

  DSA.parsePublic = function (str) {
    str = hlp.unpackData(str)
    str = str.substring(2)  // \x00\x00
    str = hlp.parseStr(str)
    return {
        p: hlp.retMPI(str[0])
      , q: hlp.retMPI(str[1])
      , g: hlp.retMPI(str[2])
      , y: hlp.retMPI(str[3])
    }
  }

  //@Edit: AJ
  DSA.parsePrivate = function (str) {
    str = hlp.unpackData(str)
    str = str.substring(2)  // \x00\x00
    str = hlp.parseStr(str)
    return {
        p: hlp.retMPI(str[0])
      , q: hlp.retMPI(str[1])
      , g: hlp.retMPI(str[2])
      , x: hlp.retMPI(str[3])
      , y: hlp.retMPI(str[4])
    }
  }

  DSA.verify = function (key, m, r, s) {
    if (!hlp.between(r, ZERO, key.q) || !hlp.between(s, ZERO, key.q))
      return false

    var hm = SHA1.SHA1(m)
    hm = BigInt.str2bigInt(hm.toString(SHA1.enc.Hex), 16)

    var w = BigInt.inverseMod(s, key.q)
    var u1 = BigInt.multMod(hm, w, key.q)
    var u2 = BigInt.multMod(r, w, key.q)

    u1 = BigInt.powMod(key.g, u1, key.p)
    u2 = BigInt.powMod(key.y, u2, key.p)

    var v = BigInt.mod(BigInt.multMod(u1, u2, key.p), key.q)

    return BigInt.equals(v, r)
  }

}).call(this)
