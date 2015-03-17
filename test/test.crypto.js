
/////////////////////////////////////////////////////////////////////////////////
// TOOLS

function errorExpected(done) {
    return function (x) {
        if (x.constructor !== cryptoe.Error)
            done(new Error("Cryptoe error expected"));
        else
            done();
    }
}

/////////////////////////////////////////////////////////////////////////////////
// TESTS

describe('Crypto', function(){

    describe('random', function(){

        it('generates a message of the requested length', function() {
            var m = cryptoe.random(100);
            assert.equal(m.len(), 100);
        });

        it('requires parameter (length)', function() {
            assert.throws(function() {
                cryptoe.random();
            }, cryptoe.Error);
        });

    });  

    describe('Symmetric encryption', function(){

        it('works for some messages', function(done) {
            co(function*(done){
                var m = cryptoe.messageFromString('ala ma kota w kącie');
                var key = yield cryptoe.generateSymmetricKey();
                var e = yield key.encrypt(m);
                var d = yield key.decrypt(e);
                assert.equal(m.toHexString(), d.toHexString());
            }).then(done,done);
        });

        it('works for long messages', function(done) {
            co(function*(){
                var m = cryptoe.random(50000);
                var key = yield cryptoe.generateSymmetricKey();
                var e = yield key.encrypt(m);
                var d = yield key.decrypt(e);
                assert.equal(m.toHexString(), d.toHexString());
            }).then(done,done);
        });

        it('conversion of keys to/from messages works as expected', function(done) {
            co(function*(){
                var m = cryptoe.messageFromString('ala ma kota w kącie');
                var key = yield cryptoe.generateSymmetricKey();
                // encode and decode the key
                var key1 = yield cryptoe.symmetricKeyFromMessage(yield key.asMessage());
                // encrypt with the original key, decrypt with the encoded and decoded
                var d = yield key1.decrypt(yield key.encrypt(m));
                assert.equal(m.toString(), d.toString());
            }).then(done,done);
        });

        it('works for some fixtures', function(done) {
            co(function*(){
                var key, m, c, d;
                key = yield cryptoe.symmetricKeyFromMessage(cryptoe.messageFromHexString('68bbb32ae81b85752be3bc632293a31353f9df0a96976193474782cc13a5cdda'));
                c   = cryptoe.messageFromHexString('3d66b89160a0ad129bbab5015f416b56ada6a0b136bc44982ec003a86802e99e008801');
                d = yield key.decrypt(c);
                assert.equal(d.toString(), 'łąka!');

                key = yield cryptoe.symmetricKeyFromMessage(cryptoe.messageFromHexString("f86a785d6d684d08dfc39fff6336b1b8ae18c469f356fe3dc30ec49ce3bf0dfa"));
                c   = cryptoe.messageFromHexString("183f1f1583b28f61587d49f32fa0690a079eea13a62b02fa1219f30ee3f6d14fbd29cb");
                d = yield key.decrypt(c);
                assert.equal(d.toString(), 'łąka!');
            }).then(done,done);
        });

        it('rejects invalid ciphertexts', function(done) {
            var c   = cryptoe.messageFromHexString('3d66b89160a0ad129bbab5115f416b56ada6a0b136bc44982ec003a86802e99e008801');
            cryptoe.symmetricKeyFromMessage(cryptoe.messageFromHexString('68bbb32ae81b85752be3bc632293a31353f9df0a96976193474782cc13a5cdda'))
            .then(function (key) { 
                key.decrypt(c).then(errorExpected(done), errorExpected(done));
            });
        });
    });  

    describe('Public-key encryption', function(){

        it('works for some messages', function(done) {
            co(function*(done){
                var m = cryptoe.messageFromString('łąka!');
                var key = yield cryptoe.generateKeyPair();
                var e = yield key.encryptionKey.encrypt(m);
                var d = yield key.decryptionKey.decrypt(e);
                assert.equal(m.toHexString(), d.toHexString());
            }).then(done,done);
        });

        it('conversion of keys to/from messages works as expected', function(done) {
            co(function*(){
                var m = cryptoe.messageFromString('ala ma kota w kącie');
                var key = yield cryptoe.generateKeyPair();
                // encode and decode the key
                var encryptionKeyAsMessage = yield key.encryptionKey.asMessage();
                var decryptionKeyAsMessage = yield key.decryptionKey.asMessage();
                var encKey = yield cryptoe.encryptionKeyFromMessage(encryptionKeyAsMessage);
                var decKey = yield cryptoe.decryptionKeyFromMessage(decryptionKeyAsMessage);

                // encrypt with the decoded key and decrypt with the original one:
                var e = yield encKey.encrypt(m);
                var d = yield key.decryptionKey.decrypt(e);
                assert.equal(m.toString(), d.toString());

                // encrypt with the original key and decrypt with the decoded one:
                e = yield key.encryptionKey.encrypt(m);
                d = yield decKey.decrypt(e);
                assert.equal(m.toString(), d.toString());
            }).then(done,done);
        });

        it('works for some fixtures', function(done) {
            co(function*(done){
                var m = cryptoe.messageFromString('łąka!');
                var encryptionKey = yield cryptoe.encryptionKeyFromMessage(cryptoe.messageFromHexString('30819f300d06092a864886f70d010101050003818d0030818902818100cbaebf9d7bd19e1bfc671d6b4dd71f31367d89339b770e55489ae2e0288bfe5221107a2a1366bf19c351ad5829ea15d3fa0e8bf02e1ddb604b20a023fcb002d3f0c1e37b0475a17dba47ec5151a6f9aebd93b6fdaba937901598713deae6da55de57990afa259dc9acb7cadc9bac1919a0682150f3dc1887f0d457d36d17e58b0203010001'));
                var decryptionKey = yield cryptoe.decryptionKeyFromMessage(cryptoe.messageFromHexString('30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100cbaebf9d7bd19e1bfc671d6b4dd71f31367d89339b770e55489ae2e0288bfe5221107a2a1366bf19c351ad5829ea15d3fa0e8bf02e1ddb604b20a023fcb002d3f0c1e37b0475a17dba47ec5151a6f9aebd93b6fdaba937901598713deae6da55de57990afa259dc9acb7cadc9bac1919a0682150f3dc1887f0d457d36d17e58b020301000102818060cae2744c6b08dff3ca6cc8996d297d918f86abe7ad643a530e87d24e7278a13ee53da8d11f7aa11b98acefc0bb65341f18da9780d2df759b3e1ddbfc3108a62608d05923cccc916953521843cc2fac4af7c990a95f8e2966d810eafa5da02eb2502f0e7216d7062056acc49639ac2c4894c578ced946361c721385c7a39f41024100ed7cafad2a44dd0a7c69364816f80063dc6fcda8c32713776995df05350fe16932666a28d569c7d7ee790c04616a62b0c1f99e34e478a61504dd30d47501f457024100db8f75270da18a87f91ce41a8a8b4dc9f851d6fb3050c28087b2f05d0c4ed48632d2b9b645d535a60f495b4234e0f614ca2b528897c170e03102cabcb94637ed024100a05a4f5852311b3b08541625c8f47d76f011c1c090bca2c53f52c5ba83608ca7f632f6bd49945a2eafc3a5dc93563cfaf28eb4472c795652dcece91a9b42cd9302405c8749a4eaaeb075fb3afcba5eb6b452b08eb4dde90fafd880d79d4a695c735e16df0d9ace353b45bf5d77d31ffbca591a9645530139697b61cc3e6a685e3a45024016917879e081177d4a98e48fba1dc2f6b825079ba076e495807d8762f0a9c38a7ed1976e154048cbccc8a72199838313a56c8823c9c03e753c714aa1f208106a'));
                var e = yield encryptionKey.encrypt(m);
                var d = yield decryptionKey.decrypt(e);
                assert.equal(m.toHexString(), d.toHexString());
            }).then(done,done);
        });
    });

});  

