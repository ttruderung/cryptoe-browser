

describe('Crypto', function(){

    describe('random', function(){

        it('generates a message of the requested length', function() {
            var m = cryptoe.random(100);
            assert.equal(m.len(), 100);
        });

        it('requires parameter (length)', function() {
            assert.throws(function() {
                cryptoe.random();
            });
        });

    });  

    describe('Symmetric encryption', function(){

        it('works for some messages', function(done) {
            co(function*(){
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

    });  

});  
