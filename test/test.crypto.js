describe('Symmetric encryption', function(){

    it('works', function(done) {

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

});  

