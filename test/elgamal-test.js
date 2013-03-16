
var
vows = require('vows'),
assert = require('assert'),
BigInt = require('../lib/bigint').BigInt,
ElGamal = require("../lib/elgamal").ElGamal,
rng = require("../lib/rng");

var random = new rng.RNG();
random.autoseed();

var suite = vows.describe('ElGamal tests');

const PARAMS = {
  p: new BigInt("16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071"),
  q: new BigInt("61329566248342901292543872769978950870633559608669337131139375508370458778917"),
  g: new BigInt("14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533")
};

var LIST_OF_PLAINTEXTS = [BigInt.ONE, new BigInt("2"), new BigInt("3"), new BigInt("4")];
LIST_OF_PLAINTEXTS.forEach(function(p, i) {
  LIST_OF_PLAINTEXTS[i] = new ElGamal.Plaintext(p);
});


// additional utils
assert.isBigInt = function(bi) {
  assert.isObject(bi);
};

assert.isPublicKey = function(pk) {
  assert.isObject(pk);
  assert.isBigInt(pk.y);
  assert.isBigInt(pk.p);
  assert.isBigInt(pk.q);
  assert.isBigInt(pk.g);
};

assert.isSecretKey = function(sk) {
  assert.isPublicKey(sk.pk);
  assert.isBigInt(sk.x);
};

assert.isCiphertext = function(ciphertext) {
  assert.isObject(ciphertext);
  assert.isBigInt(ciphertext.alpha);
  assert.isBigInt(ciphertext.beta);
  assert.isPublicKey(ciphertext.pk);
};

assert.isDLogProof = function(proof, pk) {
  assert.isBigInt(proof.commitment);
  assert.isBigInt(proof.challenge);
  assert.isBigInt(proof.response);

  assert.ok(proof.challenge.compareTo(pk.q) < 0);
  assert.ok(proof.response.compareTo(pk.q) < 0);
  assert.ok(proof.commitment.compareTo(pk.p) < 0);
};

assert.isDDHProof = function(proof, pk) {
  assert.isObject(proof.commitment);
  assert.isBigInt(proof.commitment.A);
  assert.isBigInt(proof.commitment.B);

  assert.isBigInt(proof.challenge);
  assert.isBigInt(proof.response);
  
  assert.ok(proof.challenge.compareTo(pk.q) < 0);
  assert.ok(proof.response.compareTo(pk.q) < 0);
};

assert.isDisjunctiveProof = function(proof, pk) {
  assert.isArray(proof.proofs);
  proof.proofs.forEach(function(p) {
    assert.isDDHProof(p, pk);
  });
};

var SK = null;

var CHALLENGE_GENERATOR = function(stuff) {return new BigInt("12345");}

suite.addBatch({
  "create eg params": {
    topic: function() {
      return new ElGamal.Params(PARAMS.p, PARAMS.q, PARAMS.g);
    },
    "looks good": function(params) {
      assert.isObject(params);
      assert.isObject(params.p);
      assert.isObject(params.q);
      assert.isObject(params.g);
    },
    "can be serialized and reserialized": function(params) {
      var serialized = params.toJSONObject();
      assert.isString(serialized.p);
      assert.isString(serialized.q);
      assert.isString(serialized.g);
      assert.equal(serialized.p, params.p.toString());
      assert.equal(serialized.q, params.q.toString());
      assert.equal(serialized.g, params.g.toString());

      var newParams = ElGamal.Params.fromJSONObject(serialized);
      assert.ok(newParams.p.equals(params.p));
      assert.ok(newParams.q.equals(params.q));
      assert.ok(newParams.g.equals(params.g));
    },
    "generate a keypair": {
      topic: function(params) {
        return params.generate();
      },
      "looks good": function(sk) {
        assert.isSecretKey(sk);
        SK = sk;
      },
      "prove knowledge of secret key": {
        topic: function(sk) {
          return sk.proveKnowledge(CHALLENGE_GENERATOR);
        },
        "which looks good": function(proof) {
          assert.isDLogProof(proof, SK.pk);
        },
        "which is valid": function(proof) {
          assert.ok(SK.pk.verifyKnowledgeOfSecretKey(proof, CHALLENGE_GENERATOR));
        }
      },
      "and use it to encrypt" : {
        topic: function(sk) {
          return ElGamal.encrypt(sk.pk, new ElGamal.Plaintext(BigInt.ONE, sk.pk));
        },
        "returns a ciphertext": function(ciphertext) {
          assert.isCiphertext(ciphertext);
          assert.ok(!BigInt.ONE.equals(ciphertext.alpha));
          assert.ok(!BigInt.ONE.equals(ciphertext.beta));
        },
        "which when decrypted": {
          topic: function(ciphertext) {
            return SK.decrypt(ciphertext);
          },
          "returns the right answer": function(recoveredPlaintext) {
            assert.ok(BigInt.ONE.equals(recoveredPlaintext.m));
          }
        },
        "from which we get a decryption factor": {
          topic: function(ciphertext) {
            return SK.decryptionFactor(ciphertext);
          },
          "and it looks good": function(decFactor) {
            assert.isBigInt(decFactor);
            assert.ok(!BigInt.ONE.equals(decFactor));
          }
        },
        "which is decrypted with proof": {
          topic: function(ciphertext) {
            return SK.decryptAndProve(ciphertext, CHALLENGE_GENERATOR);
          },
          "contains a proof" : function(result) {
            assert.isDDHProof(result.proof, result.plaintext.pk);
          },
          "yields the right plaintext": function(result) {
            assert.ok(BigInt.ONE.equals(result.plaintext.m));
          },
          "and the proof" : {
            topic: function(result, ciphertext) {
              return ciphertext.verifyDecryptionProof(result.plaintext, result.proof, CHALLENGE_GENERATOR);
            },
            "works out": function(result) {
              assert.ok(result);
            }
          }
        },
        "from which we generate a decryption factor and proof": {
          topic: function(ciphertext) {
            return SK.decryptionFactorAndProof(ciphertext, CHALLENGE_GENERATOR);
          },
          "and it looks good": function(result) {
            assert.isBigInt(result.decryption_factor);
            assert.ok(!BigInt.ONE.equals(result.decryption_factor));

            assert.isDDHProof(result.decryption_proof, SK.pk);
          },
          "and when it's verified": {
            topic: function(result, ciphertext) {
              return SK.pk.verifyDecryptionFactor(ciphertext, result.decryption_factor, result.decryption_proof, CHALLENGE_GENERATOR);
            },
            "works out": function(result) {
              assert.ok(result);
            }
          }
        }
      },
      "use it to encrypt two values which we homomorphically combine": {
        topic: function(sk) {
          var g_squared = sk.pk.g.modPow(BigInt.TWO, sk.pk.p);
          var g_cubed = sk.pk.g.modPow(new BigInt("3"), sk.pk.p);
          
          var ciph1 = ElGamal.encrypt(sk.pk, new ElGamal.Plaintext(g_squared));
          var ciph2 = ElGamal.encrypt(sk.pk, new ElGamal.Plaintext(g_cubed));
          
          return ciph1.multiply(ciph2);
        },
        "which yields a ciphertext": function(ciphertext) {
          assert.isCiphertext(ciphertext);
        },
        "and which, when decrypted": {
          topic: function(ciphertext, sk) {
            return sk.decrypt(ciphertext);
          },
          "returns the right result, homomorphically speaking" : function(recoveredPlaintext) {
            var g_to_the_5th = SK.pk.g.modPow(new BigInt("5"), SK.pk.p);
            assert.ok(g_to_the_5th.equals(recoveredPlaintext.m));
          }
        }
      },
      "use it to encrypt a value" : {
        topic: function(sk) {
          var plaintext = new ElGamal.Plaintext(BigInt.ONE);
          var r = random.randomInteger(sk.pk.q);
          var ciph = ElGamal.encrypt(sk.pk, plaintext, r);

          return {ciph: ciph, r:r, plaintext: plaintext, pk: sk.pk};
        },
        "and generate a proof of encryption": {
          topic: function(stuff, sk) {
            var proof = stuff.ciph.generateProof(stuff.plaintext, stuff.r, CHALLENGE_GENERATOR);
            return {stuff: stuff, proof: proof};
          },
          "which is well formed": function(stuffAndProof) {
            assert.isDDHProof(stuffAndProof.proof, stuffAndProof.stuff.pk);
          },
          "which is valid": function(stuffAndProof) {
            assert.ok(stuffAndProof.stuff.ciph.verifyProof(stuffAndProof.stuff.plaintext, stuffAndProof.proof, CHALLENGE_GENERATOR));
          }
        },
        "and simulate a proof of encryption": {
          topic: function(stuff, sk) {
            var proof = stuff.ciph.simulateProof(new ElGamal.Plaintext(BigInt.TWO), new BigInt("12345"));
            return {stuff: stuff, proof: proof};
          },
          "which is valid": function(stuffAndProof) {
            assert.isDDHProof(stuffAndProof.proof, stuffAndProof.stuff.pk);
            assert.ok(stuffAndProof.stuff.ciph.verifyProof(new ElGamal.Plaintext(BigInt.TWO), stuffAndProof.proof, CHALLENGE_GENERATOR));
          }
        },
        "and generate a disjunctive proof of encryption" : {
          topic: function(stuff, sk) {
            var proof = stuff.ciph.generateDisjunctiveProof(LIST_OF_PLAINTEXTS, 0, stuff.r, CHALLENGE_GENERATOR);

            return {stuff: stuff, proof: proof};
          },
          "which is valid": function(stuffAndProof) {
            assert.isDisjunctiveProof(stuffAndProof.proof, stuffAndProof.stuff.pk);
            assert.ok(LIST_OF_PLAINTEXTS, stuffAndProof.proof, CHALLENGE_GENERATOR);
          }
        }
      }
    }
  }
});

suite.export(module);
