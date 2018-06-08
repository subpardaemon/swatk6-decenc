var tester = require("@swatk6/tester");
var thistest = new tester();

try {
    var decenc = require("./index.js");
    var dinst = new decenc({'key':'agarjag','hashkey':'hashish'});
    var encoded = dinst.encode("laughs at a dinner party");
    thistest.addResponse(encoded,null,"must produce a null result in encryption");
    thistest.addResponse(dinst.lastError,"key_length","must produce an error of key_length");
    encoded = dinst.encode("laughs at a dinner party","01234567890123456789012345678901");
    if (encoded===null) {
	thistest.addResponse(dinst.lastError,"","error in encryption");
    }
    var decoded = dinst.decode(encoded.block,"bad_key");
    thistest.addResponse(decoded,null,"must produce a null result in decryption");
    thistest.addResponse(dinst.lastError,"key_length","must produce an error of key_length");
    decoded = dinst.decode(encoded.block,"0123456789012345678901234567890x");
    thistest.addResponse((decoded!=="laughs at a dinner party"),true,"must produce true as the decryption key is wrong");
    decoded = dinst.decode(encoded.block,"01234567890123456789012345678901");
    if (decoded===null) {
	thistest.addResponse(dinst.lastError,"","error in decryption");
    }
    thistest.addResponse(decoded,"laughs at a dinner party");
}
catch(e) {
    thistest.addResponse(e,'a normal test run','exception in main');
}
if (thistest.matchResponses()===false) {
    process.exit(1);
} else {
    process.exit(0);
}
