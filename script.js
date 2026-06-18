/* Contact form — hashcash proof-of-work, challenge-on-submit.
   Flow: POST the form. If the server replies with a JSON challenge
   {challenge, sig, target}, search for an integer nonce such that the first
   4 bytes of SHA-256(challenge + ":" + nonce), as a big-endian integer, are
   <= target; then re-POST with challenge,sig unchanged plus the nonce. The
   visitor just presses Send; the search runs in the browser. No library. */
(function () {
  "use strict";
  var form = document.getElementById("form");
  if (!form) return;
  var statusTxt = form.querySelector(".status-area span");
  var ENDPOINT = form.getAttribute("action") || "message.php";
  var busy = false;

  /* --- compact synchronous SHA-256, returns the first 32 bits of the digest
         (the first 4 bytes, big-endian, as an unsigned integer) --- */
  var K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  var W = new Uint32Array(64);
  function sha256_first32(msg) {
    var len = msg.length, bitLen = len * 8;
    var total = ((len + 8) >> 6) * 64 + 64;
    var bytes = new Uint8Array(total);
    for (var i = 0; i < len; i++) bytes[i] = msg.charCodeAt(i) & 0xff;
    bytes[len] = 0x80;
    var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    bytes[total-8]=(hi>>>24)&255; bytes[total-7]=(hi>>>16)&255; bytes[total-6]=(hi>>>8)&255; bytes[total-5]=hi&255;
    bytes[total-4]=(lo>>>24)&255; bytes[total-3]=(lo>>>16)&255; bytes[total-2]=(lo>>>8)&255; bytes[total-1]=lo&255;
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    for (var b = 0; b < total; b += 64) {
      for (var i = 0; i < 16; i++) { var j = b + i*4; W[i] = (bytes[j]<<24)|(bytes[j+1]<<16)|(bytes[j+2]<<8)|bytes[j+3]; }
      for (var i = 16; i < 64; i++) {
        var x = W[i-15], y = W[i-2];
        var s0 = ((x>>>7)|(x<<25)) ^ ((x>>>18)|(x<<14)) ^ (x>>>3);
        var s1 = ((y>>>17)|(y<<15)) ^ ((y>>>19)|(y<<13)) ^ (y>>>10);
        W[i] = (W[i-16] + s0 + W[i-7] + s1) | 0;
      }
      var a=h0,bb=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
      for (var i = 0; i < 64; i++) {
        var S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + W[i]) | 0;
        var S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
        var maj = (a & bb) ^ (a & c) ^ (bb & c);
        var t2 = (S0 + maj) | 0;
        hh=g; g=f; f=e; e=(d+t1)|0; d=c; c=bb; bb=a; a=(t1+t2)|0;
      }
      h0=(h0+a)|0; h1=(h1+bb)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+hh)|0;
    }
    return h0 >>> 0;
  }

  function setStatus(msg, color) {
    if (!statusTxt) return;
    statusTxt.style.color = color; statusTxt.style.display = "block"; statusTxt.innerText = msg;
  }
  function done(msg, color, reset) {
    busy = false; form.classList.remove("disabled"); setStatus(msg, color);
    if (reset) { form.reset(); setTimeout(function () { if (statusTxt) statusTxt.style.display = "none"; }, 4000); }
  }

  /* search for a nonce, fill hidden fields, then cb() */
  function solve(ch, cb) {
    var target = ch.target >>> 0;
    var prefix = ch.challenge + ":";
    var nonce = 0;
    (function chunk() {
      var end = nonce + 5000;
      for (; nonce < end; nonce++) {
        if (sha256_first32(prefix + nonce) <= target) {
          form.challenge.value = ch.challenge;
          form.sig.value = ch.sig;
          form.nonce.value = nonce;
          cb(); return;
        }
      }
      setTimeout(chunk, 0);   // yield so the page stays responsive
    })();
  }

  /* POST; allowSolve guards against looping if a fresh proof is still refused */
  function post(allowSolve) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", ENDPOINT, true);
    xhr.onload = function () {
      if (xhr.status !== 200) { done("Something went wrong", "orange"); return; }
      var txt = (xhr.responseText || "").trim();
      var ch = null;
      try { var j = JSON.parse(txt); if (j && j.need_proof) ch = j; } catch (e) {}
      if (ch) {
        if (!allowSolve) { done("Failed to send — please retry", "orange"); return; }
        solve(ch, function () { post(false); });
        return;
      }
      if (txt === "1")      done("Your message has been sent", "#0a0", true);
      else if (txt === "3") done("Please enter a real email address", "orange");
      else if (txt === "4") done("Please enter an email and a message", "orange");
      else                  done("Failed to send your message", "orange");
    };
    xhr.onerror = function () { done("Something went wrong", "orange"); };
    xhr.send(new FormData(form));
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (busy) return;
    if (!form.email.value.trim() || !form.message.value.trim()) {
      setStatus("Please enter an email and a message", "orange"); return;
    }
    busy = true; form.classList.add("disabled");
    setStatus("Sending your message…", "#0a0");
    post(true);
  });
})();
