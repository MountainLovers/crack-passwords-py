// const CryptoJS = require('crypto-js');
const sjcl = require('./sjcl.js');
//const sjcl = require('/home/zzjzxh/sjcl-extended/src');
const bnjs = require('bn.js');

// var one = new bnjs('1',10);
var one = new sjcl.bn('1');
// get prime p from https://safecurves.cr.yp.to/field.html
var bnp = new bnjs('115792089210356248762697446949407573530086143415290314195533631308867097853951', 10);
var sbnp = bnjs2sjclbn(bnp);
var r = sjcl.ecc.curves.c256.r;
// console.log("bnp:   "+bnp.toString("hex"));
// console.log("sbnp:   "+sbnp.toString());
// console.log("r:   "+r.toString());


var k = new sjcl.bn("e3dcf52256d55753f0f549351de6d3fddcc585ed4c95b46dcc5cc8a561c3322b");

/**
 * SHA256 implemented by CryptoJS
 * @param {*} passwd_str 
 * @return {String} SHA256 Hash Result
 */
var hash = function (passwd_str) {
    // var hashbits = CryptoJS.SHA256(passwd_str);
    var hashbits = sjcl.hash.sha256.hash(passwd_str);
    // return hashbits.toString(CryptoJS.enc.hex);
    return sjcl.codec.hex.fromBits(hashbits);
}


// Trans sjcl bn to bnjs bn
/**
 * 
 * @param {*} sjclbn 
 * @return bn:js bn object
 */
function sjclbn2bnjs(sjclbn) {
    var str = sjcl.codec.hex.fromBits(sjclbn.toBits());
    // console.log("sjclstr:"+str);
    return new bnjs(str, 16);
}
// Trans bnjs bn to sjcl bn
/**
 * 
 * @param {*} bnjsbn 
 * @return sjcl.bn bn object
 */
function bnjs2sjclbn(bnjsbn) {
    var str = bnjsbn.toString(16);
    return new sjcl.bn(str);
}

// Hash into Curve, H'()
/**
 * 
 * @param {*} passwd
 */
function hashIntoEC(passwd) {
    passwd_hex = hash(passwd);
    var curve = sjcl.ecc.curves.c256;
    // G = curve.G;
    // x = G.x;
    // y = G.y;
    // console.log("G.x:"+sjcl.codec.hex.fromBits(x.toBits()));
    // console.log("G.y:"+sjcl.codec.hex.fromBits(y.toBits()));
    // console.log("G:"+sjcl.codec.hex.fromBits(G.toBits()));

    // get y^2 = x^3+a*x+b params
    var a = new sjcl.bn(curve.a.toString());
    var bna = sjclbn2bnjs(a);
    var b = new sjcl.bn(curve.b.toString());
    var bnb = sjclbn2bnjs(b);

    // init x
    var x = new sjcl.bn(passwd_hex);
    // var bnx = sjclbn2bnjs(x);

    var redp = bnjs.red(bnp);
    
    var P;

    var found = false;

    while (!found) {
        // console.log("in!");
        // var bns = bnb.add(bnx.mul(bna.add(bnx.mul(bnx))));
        // b + (x*(a+(x^2))) => b+ax+x^3
        var s = b.add(x.mul(a.add(x.mul(x).normalize())).normalize());
        var bns = sjclbn2bnjs(s);

        // console.log("bns :",bns.toString("hex"));
        // console.log("bns2:",bns2.toString("hex"));
        // console.log("compare:",bns.eq(bns2));
        var reds = bns.toRed(redp);
        try {
            // try to calculate modular square root
            bny = reds.redSqrt();
            // console.log("in1!!!");
            
            // calculate point
            y = bnjs2sjclbn(bny);
            // xx = bnjs2sjclbn(bnx);
            P = new sjcl.ecc.point(
                sjcl.ecc.curves.c256,
                new sjcl.bn.prime.p256(x.toString()),
                new sjcl.bn.prime.p256(y.toString())
            );
            if (P.isValid()) found = true;
        } catch {
        } finally {
            // bnx = bnx.add(one);
            x = x.add(one);
        }
    }
    return P;
}

// F_k(x) = H(x, (H'(x))^k)
/**
 * 
 * @param {String} x 
 * @param {*} k 
 * @return sjcl.point object
 */
var Fk = function(x) {
    hash_point = hashIntoEC(x);
    test = hash_point.mult(k);
    hpxk = hash_point.mult(k).toBits();
    hpxk_str = sjcl.codec.hex.fromBits(hpxk);
    str = x+hpxk_str;
    // console.log("first :"+str);
    return hash(str);
}

/**
 * generate rho, use sjcl.random. should collect entropy, but this function can work without that.
 * @return sjcl.bn object
 */
function getRho() {
    var numWords = 8;
    var rand;
    if (sjcl.random.isReady() > 0) {
        // console.log("isReady:"+sjcl.random.isReady());
        rand_bits = sjcl.random.randomWords(numWords);
        // rand = sjcl.bn.fromBits(rand_bits); another method, but don't know the difference.
        rand_str = sjcl.codec.hex.fromBits(rand_bits);
        rand = new sjcl.bn(rand_str);
        // make sure rho belong to Zq
        rand = rand.mod(r);

        // use bn:js
        // rand = new bnjs(rand_str, "hex");
        // console.log("rand    :"+rand.toString("hex"));
        return rand;
    } else {
        console.log("sjcl random not ready!");
    }
}

/**
 * calculate alpha = (H'(pwd|domain))^rho
 * @param {String} str 
 * @param {sjcl.bn} rho 
 * @return sjcl.point object
 */
function getAlpha(str, rho) {
    var EC_hash_result = hashIntoEC(str);
    var alpha = EC_hash_result.mult(rho);
    return alpha;
}

/**
 * simulate the device calculate beta, only for test protocol. 
 * @param {sjcl.point} alpha 
 * @param {sjcl.bn} k 
 * @return sjcl.point
 */
function getBetaOnDevice(alpha, k) {
    return alpha.mult(k);
}

/**
 * reconstruct rwd using beta and rho
 * @param {sjcl.point} beta 
 * @param {sjcl.bn} rho 
 * @return String rwd 
 */
function reconstructRWD(beta, rho) {
    // Question: what's the difference between r and p? why use p in calculating point, while use r in calculating inverse?
    var rho_inverse = rho.inverseMod(r);
    beta_power_rho_inverse_str = sjcl.codec.hex.fromBits(beta.mult(rho_inverse).toBits());
    // console.log("second:"+passwd + domain + beta_power_rho_inverse_str);
    var rwd = hash(passwd + domain + beta_power_rho_inverse_str);
    // console.log("reconstruct rwd:"+rwd);
    return rwd;
}

function applyConstraints(hash, size, nonalphanumeric) {
    var startingSize = size - 4;  // Leave room for some extra characters
    var result = hash.substring(0, startingSize);
    var extras = hash.substring(startingSize).split('');

    // Some utility functions to keep things tidy
    function nextExtra() { return extras.length ? extras.shift().charCodeAt(0) : 0; }
    function nextExtraChar() { return String.fromCharCode(nextExtra()); }
    function rotate(arr, amount) { while(amount--) arr.push(arr.shift()) }
    function between(min, interval, offset) { return min + offset % interval; }
    function nextBetween(base, interval) { 
        return String.fromCharCode(between(base.charCodeAt(0), interval, nextExtra()));
    }
    function contains(regex) { return result.match(regex); }

    // Add the extra characters
    result += (contains(/[A-Z]/) ? nextExtraChar() : nextBetween('A', 26));
    result += (contains(/[a-z]/) ? nextExtraChar() : nextBetween('a', 26));
    result += (contains(/[0-9]/) ? nextExtraChar() : nextBetween('0', 10));
    result += (contains(/\W/) && nonalphanumeric ? nextExtraChar() : '+');
    while (contains(/\W/) && !nonalphanumeric) {
        result = result.replace(/\W/, nextBetween('A', 26));
    }

    // Rotate the result to make it harder to guess the inserted locations
    result = result.split('');
    rotate(result, nextExtra());
    return result.join('');
}


var hashPWD = function(password, orihashedpwd) {
    var size = password.length + 2;
    var nonalphanumeric = password.match(/\W/) != null;
    var result = applyConstraints(orihashedpwd, size, nonalphanumeric);
    return result;
}

var rwByLine = require('./file.js')
var readName = '../datasets/plaintext/myspace.txt';
var writeName = '../datasets/harden/myspace_harden.txt';
rwByLine.readWriteFileByLineWithProcess(readName,writeName,function(line){
    passwd = line.toString()
    var orirwd = Fk(passwd);
    console.log("orirwd:"+orirwd);
    var rwd = hashPWD(passwd, orirwd)
    console.log("rwd:"+rwd);
    return rwd;
})

// console.log("load sphinx-utils.js success");
// //begin simulate the procedure of protocol
// var passwd = "12345678";    // User's password to memory
// var domain = "@extensions"          // the website identity

// var orirwd = Fk(passwd+domain);
// console.log("orirwd:"+orirwd);
// var rwd = hashPWD(passwd, orirwd)
// console.log("rwd:"+rwd);




// var rho = new sjcl.bn("6cef01ffd030eff3f24febc1f1069efa1e2c384cbaee2496b143675272d0b4c6");
// console.log("rho:"+rho.toString());

// var alpha = getAlpha(passwd+domain, rho);
// console.log("alpha:"+sjcl.codec.hex.fromBits(alpha.toBits()));
// var beta = getBetaOnDevice(alpha, k);
// console.log("beta:"+sjcl.codec.hex.fromBits(beta.toBits()));
// var rwd2 = reconstructRWD(beta, rho);
// console.log("reconstruct rwd:"+rwd2);

// var hexbeta2 = "36fdc6c6bf53cc76d323c1f869e5d1a1ecf8d03cadeaf3e531340574a09408f8a177c7fc762c268060348c59fc6fbc8cf597715d29d2e0c4d7dc23562c6c40d6";
// tmpp = sjcl.codec.hex.toBits(hexbeta2);
// var beta = sjcl.ecc.curves.c256.fromBits(tmpp);
// if (beta.isValid()) {
//     console.log("success retrive beta!");
// } else {
//     console.log("unsuccess retrive beta!");
// }

// var ax = sjcl.codec.hex.fromBits(alpha.x.toBits());
// console.log("ax:"+ax);
// var ay = sjcl.codec.hex.fromBits(alpha.y.toBits());
// console.log("ay:"+ay);
/* Test inverse
// var point = hashIntoEC(passwd+domain);
// var k = new sjcl.bn(10);
// var rho = getRho();
// var rho_inverse = rho.inverseMod(r);

// var alpha = point.mult(rho);
// var beta = alpha.mult(k);
// var beta2 = beta.mult(rho_inverse);
// var right = point.mult(k);

// console.log("right:"+sjcl.codec.hex.fromBits(right.toBits()));
// console.log("beta2:"+sjcl.codec.hex.fromBits(beta2.toBits()));

// var checkrho = rho.mulmod(rho_inverse, sbnp);
// console.log("rho*inverse:"+checkrho.toString());
*/