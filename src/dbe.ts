import { AffinePoint } from "@noble/curves/abstract/curve";
import { H2CPoint, hash_to_field } from "@noble/curves/abstract/hash-to-curve";
import { bls12_381 } from "@noble/curves/bls12-381";
import { assert } from "console";

const utf8Encode = new TextEncoder();

const _appendBuffer = (buffer1: Uint8Array, buffer2: Uint8Array) => {
  let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp;
};

const stringToBytes = (msg: string) => {
  return utf8Encode.encode(msg);
};
const pointToBytes = (point: AffinePoint<bigint>) => {
  return _appendBuffer(
    bls12_381.fields.Fp.toBytes(point.x),
    bls12_381.fields.Fp.toBytes(point.y)
  );
};

const G1ToProj = (point: H2CPoint<bigint>) => {
  const affine = point.toAffine();
};

const pairing_based_broadcast_encryption = (
  number_of_users: number,
  number_of_trials: number
) => {
  console.log("Begin setup of public keys");
  let hrStart = process.hrtime();

  const channel_generator_G1 = bls12_381.G1.hashToCurve(stringToBytes("1"));
  const channel_generator_G2 = bls12_381.G2.hashToCurve(stringToBytes("1"));

  let PK_G1 = [channel_generator_G1];
  let PK_G2 = [channel_generator_G2];

  const alpha = bls12_381.fields.Fr.fromBytes(
    bls12_381.utils.randomPrivateKey()
  );

  let alpha_i = alpha;
  for (let i = 1; i <= 2 * number_of_users; i++) {
    if (i == number_of_users + 1) {
      //   PK_G1.push(0);
      //   PK_G2.push(0);
    } else {
      PK_G1.push(channel_generator_G1.multiply(alpha));
      PK_G2.push(channel_generator_G2.multiply(alpha));
    }
    alpha_i = bls12_381.fields.Fp.mul(alpha_i, alpha);
  }

  // In the general construction, each shard has a different gamma
  const gamma = bls12_381.fields.Fr.fromBytes(
    bls12_381.utils.randomPrivateKey()
  );

  const v_G1 = channel_generator_G1.multiply(gamma);
  PK_G1.push(v_G1);
  const v_G2 = channel_generator_G2.multiply(gamma);
  PK_G2.push(v_G2);

  let hrEnd = process.hrtime(hrStart);
  console.log(
    "\n\tsetup %d msec per user",
    (hrEnd[0] * 1000000 + hrEnd[1] / 1000000) / number_of_users
  );

  let PK_length = 0;
  for (const p of PK_G1) {
    PK_length += pointToBytes(p.toAffine()).length;
  }
  console.log(
    "\tPK length=" +
      PK_length / 2 +
      " bytes " +
      PK_length / 2 / number_of_users +
      " bytes per user"
  );

  console.log("End setup of public keys\n");

  console.log("Begin setup of private keys");

  let private_keys_G1: H2CPoint<bigint>[] = [];
  for (let i = 1; i <= number_of_users; i++) {
    const i_private_key = PK_G1[i].multiply(gamma);
    private_keys_G1.push(i_private_key);
  }
  console.log("End setup of private keys\n");

  console.log("Begin encryption");

  const users_allowed_to_broadcast: number[] = [];
  for (let i = 1; i <= number_of_users; i++) {
    if (Math.random() > 0.5) {
      users_allowed_to_broadcast.push(i);
    }
  }

  hrStart = process.hrtime();

  const t = bls12_381.fields.Fr.fromBytes(bls12_381.utils.randomPrivateKey());

  const K_pairing = bls12_381.pairing(
    bls12_381.G1.ProjectivePoint.fromAffine(PK_G1[number_of_users].toAffine()),
    bls12_381.G2.ProjectivePoint.fromAffine(PK_G2[1].toAffine())
  );

  const K_encrypt = bls12_381.fields.Fp12.pow(K_pairing, t);

  let C_G2 = [channel_generator_G2.multiply(t)];

  let c1_G2 = v_G2;
  for (const j of users_allowed_to_broadcast) {
    c1_G2 = c1_G2.add(PK_G2[number_of_users - j]);
  }

  c1_G2 = c1_G2.multiply(t);
  C_G2.push(c1_G2);

  hrEnd = process.hrtime(hrStart);
  console.log(
    "\tencrypt %d msec per S user",
    (hrEnd[0] * 1000000 + hrEnd[1] / 1000000) /
      users_allowed_to_broadcast.length
  );
  console.log("End encryption\n");

  // Decrypt
  hrStart = process.hrtime();
  console.log("Begin decryption");
  console.log(`\tnumber of trials=${number_of_trials}`);

  for (let k = 1; k <= number_of_trials; k++) {
    // iterate overuser doing the decryption
    let i = Math.ceil(Math.random() * (number_of_users - 1)); // select user
    console.log("user=" + i);
    let e_G1 = private_keys_G1[i].multiply(bls12_381.fields.Fp.ONE);

    for (const j of users_allowed_to_broadcast) {
      if (j != i) {
        // console.log("EG1", PK_G1[number_of_users - j + i], e_G1, e_G1.add);
        e_G1 = e_G1.add(PK_G1[number_of_users - j + i]);
      }
    }

    const K_decrypt = bls12_381.fields.Fp12.div(
      bls12_381.pairing(
        bls12_381.G1.ProjectivePoint.fromAffine(PK_G1[i].toAffine()),
        bls12_381.G2.ProjectivePoint.fromAffine(C_G2[1].toAffine())
      ),
      bls12_381.pairing(
        bls12_381.G1.ProjectivePoint.fromAffine(e_G1.toAffine()),
        bls12_381.G2.ProjectivePoint.fromAffine(C_G2[0].toAffine())
      )
    );
    // console.log("allowed to encrypt", users_allowed_to_broadcast.includes(i));
    if (users_allowed_to_broadcast.includes(i)) {
      // Assert what we encrypted and decrypted are the same

      assert(bls12_381.fields.Fp12.eql(K_decrypt, K_encrypt) === true);
    } else {
      assert(bls12_381.fields.Fp12.eql(K_decrypt, K_encrypt) === false);
    }
    console.log("End round", k);
  }
};

async function main() {
  pairing_based_broadcast_encryption(100, 2);
}

main().then(() => {
  console.log("done");
});
