const mcl = require("mcl-wasm");
const assert = require("assert");




const pairing_based_broadcast_encryption = (number_of_users, number_of_trials) => {


  console.log("Begin setup of public keys")
  let hrstart = process.hrtime();



  const channel_generator_G1 = mcl.hashAndMapToG1("1");
  let PK_G1 = [];
  PK_G1.push(channel_generator_G1);

  const channel_generator_G2 = mcl.hashAndMapToG2("1");
  let PK_G2 = [];
  PK_G2.push(channel_generator_G2);

  const alpha = new mcl.Fr();
  alpha.setByCSPRNG();

  console.log(`\tnumber of users=${number_of_users}`);
  let alpha_i = alpha;
  for (let i = 1; i <= 2 * number_of_users; i++) {
    if (i == number_of_users + 1) {
      PK_G1.push(0);
      PK_G2.push(0);
    } else {
      PK_G1.push(mcl.mul(channel_generator_G1, alpha_i));
      PK_G2.push(mcl.mul(channel_generator_G2, alpha_i));
    }
    alpha_i = mcl.mul(alpha_i, alpha);
  }

  // In the general construction, each shard has a different gamma
  const gamma = new mcl.Fr();
  gamma.setByCSPRNG();
  const v_G1 = mcl.mul(channel_generator_G1, gamma);
  PK_G1.push(v_G1);
  const v_G2 = mcl.mul(channel_generator_G2, gamma);
  PK_G2.push(v_G2);

  let hrend = process.hrtime(hrstart);
  console.log(
    "\tsetup %d usec per user",
    (hrend[0] * 1000000 + hrend[1] / 1000) / number_of_users
  );

  let PK_length = 0;
  for (const p of PK_G1) {
    if (p != 0) {
      PK_length += p.serializeToHexStr().length;
    }
  }
  console.log(
    "\tPK length=" +
      PK_length / 2 +
      " bytes " +
      PK_length / 2 / number_of_users +
      " bytes per user"
  );

  console.log("End setup of public keys\n")

  console.log("Begin setup of private keys")
  let private_keys_G1 = [0];
  for (let i = 1; i <= number_of_users; i++) {
    private_keys_G1.push(mcl.mul(PK_G1[i], gamma));
  }
  console.log("End setup of private keys\n")

  console.log("Begin encryption")

  // generate a random broadcasting list (subset of users)
  const users_allowed_to_broadcast = [];
  for (let i = 1; i <= number_of_users; i++) {
    if (Math.random() > 0.5) {
      users_allowed_to_broadcast.push(i);
    }
  }

  hrstart = process.hrtime();

  const t = new mcl.Fr();
  t.setByCSPRNG();
  const K_encrypt = mcl.pow(mcl.pairing(PK_G1[number_of_users], PK_G2[1]), t);

  let C_G2 = [];
  C_G2.push(mcl.mul(channel_generator_G2, t));

  let c1_G2 = v_G2;
  for (const j of users_allowed_to_broadcast) {
    c1_G2 = mcl.add(c1_G2, PK_G2[number_of_users + 1 - j]);
  }
  c1_G2 = mcl.mul(c1_G2, t);
  C_G2.push(c1_G2);

  hrend = process.hrtime(hrstart);
  console.log(
    "\tencrypt %d usec per S user",
    (hrend[0] * 1000000 + hrend[1] / 1000) / users_allowed_to_broadcast.length
  );
  console.log("End encryption\n")


  // Decrypt
  hrstart = process.hrtime();
  console.log("Begin decryption")
  console.log(`\tnumber of trials=${number_of_trials}`)
  for (let k = 1; k <= number_of_trials; k++) {
    // iterate overuser doing the decryption
    let i = Math.ceil(Math.random() * number_of_users); // select user
    // console.log('user='+i)
    let e_G1 = private_keys_G1[i];

    for (const j of users_allowed_to_broadcast) {
      if (j != i) {
        e_G1 = mcl.add(e_G1, PK_G1[number_of_users + 1 - j + i]);
      }
    }

    const K_decrypt = mcl.div(
      mcl.pairing(PK_G1[i], C_G2[1]),
      mcl.pairing(e_G1, C_G2[0])
    );
    if (users_allowed_to_broadcast.includes(i)) {
      // Assert what we encrypted and decrypted are the same
      assert.equal(
        K_decrypt.serializeToHexStr(),
        K_encrypt.serializeToHexStr(),
        "user=" + i
      );
    } else {
      // Assert what we encrypted and decrypted are NOT the same
      assert.notEqual(
        K_decrypt.serializeToHexStr(),
        K_encrypt.serializeToHexStr(),
        "user=" + i
      );
    }
  }

  hrend = process.hrtime(hrstart);
  console.log(
    "\tdecrypt %d usec per S user",
    (hrend[0] * 1000000 + hrend[1] / 1000) / number_of_trials / users_allowed_to_broadcast.length
  );

  console.log("End decryption")

};

async function main() {
  await mcl.init(mcl.BLS12_381); // use BLS12-381
  console.log("initizlied mcl");
  pairing_based_broadcast_encryption(1000, 5);
}

main().then(() => {
  console.log("done");
});
