/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * abstract out RNG depending on client or server.
 *
 * auto-seeding has to be requested.
 * (the seed is automatic, not the decision to auto-seed.)
 *
 * nextBytes takes a byteArray as input and populates it,
 * because that's how the cool kids do it and so we will not bikeshed.
 */

var utils = require("./utils"),
    delay = utils.delay,
    sjcl = require("./sjcl"),
    bigint = require("./bigint");

// detect if we have native crypto support
var crypto = null;
try {
  crypto = require("crypto");
} catch(e) {}

// proper boolean for whether we have native support
var IS_NATIVE = !!crypto;

function NativeRNG() {
}

NativeRNG.prototype = {
  addEntropy: function(seed_in) {
    // do nothing, natively we don't care
  },
  autoseed: function(cb) {
    // yay, don't need to do anything
    if (cb)
      delay(cb)();
  },
  nextBytes: function(byteArray) {
    var randomBytes = crypto.randomBytes(byteArray.length);
    for (var i=0; i<byteArray.length; i++)
      byteArray[i] = randomBytes[i];
  },
  randomInteger: function(max) {
    var bits = new Array(Math.floor((max.bitLength()+7)/8));
    this.nextBytes(bits);
    var buf = new Buffer(bits);
    return new bigint.BigInt(buf.toString('hex'), 16).mod(max);
  }
};

function BrowserRNG() {
  var has_getrandomvalues = false;
  try {
    has_getrandomvalues = !! window.crypto.getRandomValues;
  } catch (x) {
    // apparently just trying to touch window.crypto will
    // throw an exception on some platforms, so we have to be
    // ultra stoopid about how we do this
  }
  
  this.isSeeded = has_getrandomvalues;
}

BrowserRNG.prototype = {
  // WARNING: assumes that there's enough entropy in here to say it's 256
  addEntropy: function(seed_in) {
    sjcl.random.addEntropy(seed_in, 256);
    this.isSeeded = true;
  },
  autoseed: function(cb) {
    // this line is required because we have potentially more than
    // one RNG object, but only one sjcl.random underlying object
    // so we need to check that maybe a previous object properly seeded
    // the RNG or we will never get the seed event.
    this.isSeeded = this.isSeeded || sjcl.random.isReady();
    
    if (this.isSeeded) {
      if (cb) delay(cb)();
      return;
    } else {
      sjcl.random.addEventListener('seeded', function(blarg) {
        this.isSeeded = true;
        // no passing of arguments to the callback
        if (cb)
          cb();
      });

      // tell sjcl to start collecting some entropy      
      sjcl.random.startCollectors();
    }
  },
  nextBytes: function(byteArray) {
    var randomBytes = sjcl.random.randomWords(byteArray.length);
    for (var i=0; i<byteArray.length; i++)
      byteArray[i] = randomBytes[i];
  },
  randomInteger: function(max) {
    var bits = new Array(Math.floor((max.bitLength()+7)/8));
    this.nextBytes(bits);
    return new bigint.BigInt(sjcl.codec.hex.fromBits(random), 16).mod(max);
  }
};

exports.RNG = IS_NATIVE ? NativeRNG : BrowserRNG;

