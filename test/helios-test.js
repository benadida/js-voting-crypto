
var
vows = require('vows'),
assert = require('assert'),
ElGamal = require("../lib/elgamal").ElGamal,
HELIOS = require("../lib/helios").HELIOS,
rng = require("../lib/rng");

var random = new rng.RNG();
random.autoseed();

var suite = vows.describe('Helios Tests');

var ELECTION_JSON = '{"cast_url": "https://vote.heliosvoting.org/helios/elections/2603c4ea-7c81-11e1-9608-12313f028a58/cast", "description": "test-2012-04-01", "frozen_at": "2012-04-02 05:03:31.246109", "name": "test-2012-04-01", "openreg": true, "public_key": {"g": "14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533", "p": "16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071", "q": "61329566248342901292543872769978950870633559608669337131139375508370458778917", "y": "15564912608459845830957548926769452951320535663834308599528176361449553797711474526551687231125699921727266516993772271166270267076896384837131903390732758797350005808442248144043261533502227804066921954134598653056834290436560721379044648553599181132876775374369321494706285031374681076713998799407756329043545560635423051285885887385899656281820290627422927876626725403831405695737909081124306424566177446552142540214224570972660519923692481669148494798526120205736050542744213795615172648570726536873711233289895178559219120052062519398291177416071066746337618395854478799163677532419195792233835605998297905420365"}, "questions": [{"answer_urls": [null, null, null], "answers": ["a", "b", "c"], "choice_type": "approval", "max": 1, "min": 0, "question": "w?", "result_type": "absolute", "short_name": "w?", "tally_type": "homomorphic"}], "short_name": "test-2012-04-01", "use_voter_aliases": false, "uuid": "2603c4ea-7c81-11e1-9608-12313f028a58", "voters_hash": null, "voting_ends_at": null, "voting_starts_at": null}';

suite.addBatch({
  "load an election": {
    topic: function() {
      return HELIOS.Election.fromJSONString(ELECTION_JSON);
    },
    "looks good": function(election) {
      assert.isObject(election);
      assert.isString(election.cast_url);
      assert.isString(election.uuid);
      assert.isString(election.description);
      assert.isString(election.short_name);
      assert.isString(election.name);
      assert.isArray(election.questions);
    },
    // we don't expect canonicalization anymore
    "re-serialization and re-deserialization yields same fields": function(election) {
      var reparsed_fields = JSON.parse(election.toJSON());
      assert.isObject(reparsed_fields);
      assert.isString(reparsed_fields.cast_url);
      assert.isString(reparsed_fields.uuid);
      assert.isString(reparsed_fields.description);
      assert.isString(reparsed_fields.short_name);
      assert.isString(reparsed_fields.name);
      assert.isArray(reparsed_fields.questions);
    },
    "create an encrypted answer": {
      topic: function(election) {
        var ea = new HELIOS.EncryptedAnswer(election.questions[0], 1, election.public_key);
        return ea;
      },
      "looks ok": function(ea) {
        assert.isObject(ea);
        assert.isArray(ea.choices);
        assert.isArray(ea.randomness);
        assert.isArray(ea.individual_proofs);
        assert.isObject(ea.overall_proof);
      },
      "verifying encryption": {
        topic: function(ea, election) {
          return ea.verifyEncryption(election.questions[0], election.pk);
        },
        "verifies": function(result) {
          assert.ok(result);
        }
      },
      "after clearing the plaintexts": {
        topic: function(ea, election) {
          ea.clearPlaintexts();
          return ea;
        },
        "has no more plaintexts": function(ea) {
          assert.isNull(ea.answer);
          assert.isNull(ea.randomness);
        }
      },
      "after serializing": {
        topic: function(ea, election) {
          return ea.toJSONObject();
        },
        "looks good": function(ea_serialized) {
          assert.isObject(ea_serialized);
          assert.isArray(ea_serialized.choices);
          assert.isArray(ea_serialized.individual_proofs);
          assert.isArray(ea_serialized.overall_proof);
        },
        "and de-serializing": {
          topic: function(ea_serialized, ea, election) {
            return HELIOS.EncryptedAnswer.fromJSONObject(ea_serialized, election);
          },
          "still verifies": function(ea_reserialized) {
            assert.isObject(ea_reserialized);
            assert.isArray(ea_reserialized.choices);
            assert.isUndefined(ea_reserialized.randomness);
            assert.isArray(ea_reserialized.individual_proofs);
            assert.isObject(ea_reserialized.overall_proof);
          }
        }
      }
    }
  }
});

suite.export(module);
