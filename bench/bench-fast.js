var nacl = require('./nacl-fast');

var m0 = new Uint8Array(new Buffer('Helloword, Am Tom ...'));
m0[0] = 0x68;

var ska = new Uint8Array(32);
for (var i = 0; i < ska.length; i ++) ska[i] = 0;
var kpa = nacl.box.keyPair.fromSecretKey(ska);
console.log('\nkpa:'+JSON.stringify(kpa));

var skb = new Uint8Array(32);
for (var i = 0; i < skb.length; i ++) skb[i] = 1;
var kpb = nacl.box.keyPair.fromSecretKey(skb);
console.log('\nkpb:'+JSON.stringify(kpb));

var nonce = new Uint8Array(24);
for (var i = 0; i < nonce.length; i ++) nonce[i] = 0;
console.log('\nnonce:'+JSON.stringify(nonce));

var cab = nacl.box(m0, nonce, kpb.publicKey, kpa.secretKey);
console.log('\ncab:'+JSON.stringify(cab));


console.log('\nm0:'+JSON.stringify(m0));

var mba = nacl.box.open(cab, nonce, kpa.publicKey, kpb.secretKey);
console.log('\nmba:'+JSON.stringify(mba));

var nm0 = mba.toString('utf-8');
console.log('\nnm0:'+nm0);

// Stress on secretBox

// shared key
var i;

var shk = new Uint8Array(nacl.secretbox.keyLength);
for (i = 0; i < shk.length; i ++)
	shk[i] = 0x66;

var nonce = new Uint8Array(nacl.secretbox.nonceLength);
for (i = 0; i < nonce.length; i ++)
	nonce[i] = 0;

// messages
var m0 = "Helloword, Am Tom ...";

// cipher A -> B
console.log("streess on secret box@"+m0);

for (var t = 0; t < 19; t ++, m0 += m0) {	
	var mb0 = new Uint8Array(new Buffer(m0));
			
	console.log("\n\n\tstreess/"+(mb0.length/1000.0) +"kB: " + t + " times");
    ///console.log('mb0:'+JSON.stringify(mb0));

	console.log("secret box ...@" + new Date().getTime());
	var cab = nacl.secretbox(mb0, nonce, shk);
	console.log("... secret box@" + new Date().getTime());
    ///console.log('cab:'+JSON.stringify(cab));

	console.log("\nsecret box open ...@" + new Date().getTime());
	var mba = nacl.secretbox.open(cab, nonce, shk);
	console.log("... secret box open@" + new Date().getTime());
    ///console.log('mba:'+JSON.stringify(mba));
}

// signature
var m1 = "Helloword, Am Tom ...";
var seed = new Uint8Array(32); for (var i = 0; i < 32; i ++) seed[i] = 0x66;
var sigk = nacl.sign.keyPair.fromSeed(seed);
console.log('\nsigk:'+JSON.stringify(sigk));

var sig = nacl.sign(new Uint8Array(new Buffer(m1)), sigk.secretKey);
console.log('\nsignature:'+JSON.stringify(sig));

var msg = nacl.sign.open(sig, sigk.publicKey);
console.log('\nveriry:'+JSON.stringify(msg));

// hash
var hash = nacl.hash(new Uint8Array(new Buffer(m1)));
console.log('\nhash@'+m1+'/'+new Buffer(m1).length +':'+JSON.stringify(hash));
