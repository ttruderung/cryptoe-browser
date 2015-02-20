

describe('Crypto', function(){

    describe('random', function(){

        it('generates a message of the requested length', function() {
            var m = cryptoe.random(100);
            console.log(m.toHexString());
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
            // take some message m
            var m = cryptoe.messageFromString('ala ma kota w kącie');
            // generate a symmetric key
            cryptoe.generateSymmetricKey().then(function(key) { 
                key.encrypt(m) // encrypt m using this key
                   .then(key.decrypt) // decrypt the result of encryption
                   .then(function(result){  // take the result of decryption
                        // It should be equal to m
                        assert.equal(m.toHexString(), result.toHexString());
                        done();
                   })
                   .catch(done);
            });
        })

        it('works for long messages', function(done) {
            // take some message m
            var m = cryptoe.random(50000);
            // generate a symmetric key
            cryptoe.generateSymmetricKey().then(function(key) { 
                key.encrypt(m) // encrypt m using this key
                   .then(key.decrypt) // decrypt the result of encryption
                   .then(function(result){  // take the result of decryption
                        // It should be equal to m
                        assert.equal(m.toHexString(), result.toHexString());
                        done();
                   })
                   .catch(done);
            });
        })

    });  

});  
