import { decrypt as ecDecrypt, encrypt as ecEncrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";

export const ecCurveSecp256k1 = new EC("secp256k1");

export type PointHex = {
  x: string | null;
  y: string | null;
};

export function randomSelection(arr: number[], num: number): number[] {
  if (num > arr.length) throw new Error("trying to select more elements than available");
  const selected: number[] = [];
  const slice = arr.slice();
  while (selected.length < num) {
    selected.push(slice.splice(Math.floor(Math.random() * slice.length), 1)[0]);
  }
  return selected;
}

export function ecPoint(ecCurve: EC, p: PointHex): curve.base.BasePoint {
  if (p.x === null && p.y === null) {
    return ecCurve.curve.g.add(ecCurve.curve.g.neg());
  }
  return ecCurve.keyFromPublic({ x: p.x.padStart(64, "0"), y: p.y.padStart(64, "0") }).getPublic();
}

export function hexPoint(p: curve.base.BasePoint): PointHex {
  if (p.isInfinity()) {
    return { x: null, y: null };
  }
  return { x: p.getX().toString(16, 64), y: p.getY().toString(16, 64) };
}

export type EncryptedMessage = {
  ciphertext: string;
  ephemPublicKey: string;
  iv: string;
  mac: string;
};

// Wrappers around ECC encrypt/decrypt to use the hex serialization
export async function encrypt(publicKey: Buffer, msg: Buffer): Promise<EncryptedMessage> {
  const encryptedDetails = await ecEncrypt(publicKey, msg);
  return {
    ciphertext: encryptedDetails.ciphertext.toString("hex"),
    ephemPublicKey: encryptedDetails.ephemPublicKey.toString("hex"),
    iv: encryptedDetails.iv.toString("hex"),
    mac: encryptedDetails.mac.toString("hex"),
  };
}

export async function decrypt(privKey: Buffer, msg: EncryptedMessage): Promise<Buffer> {
  const bufferEncDetails = {
    ciphertext: Buffer.from(msg.ciphertext, "hex"),
    ephemPublicKey: Buffer.from(msg.ephemPublicKey, "hex"),
    iv: Buffer.from(msg.iv, "hex"),
    mac: Buffer.from(msg.mac, "hex"),
  };

  return ecDecrypt(privKey, bufferEncDetails);
}

export function generatePolynomial(degree: number, yIntercept: BN, randomElement: () => BN): BN[] {
  const res: BN[] = [];
  let i = 0;
  if (yIntercept !== undefined) {
    res.push(yIntercept);
    i++;
  }
  for (; i <= degree; i++) {
    res.push(randomElement());
  }
  return res;
}
export function getShare(polynomial: BN[], index: BN | number, modulus: BN) {
  let res = new BN(0);
  for (let i = 0; i < polynomial.length; i++) {
    const term = polynomial[i].mul(new BN(index).pow(new BN(i)));
    res = res.add(term.umod(modulus));
  }
  return res.umod(modulus);
}

export function dotProduct(arr1: BN[], arr2: BN[], modulus?: BN) {
  if (arr1.length !== arr2.length) {
    throw new Error("arrays of different lengths");
  }
  let sum = new BN(0);
  for (let i = 0; i < arr1.length; i++) {
    sum = sum.add(arr1[i].mul(arr2[i]));
    if (modulus) {
      sum = sum.umod(modulus);
    }
  }
  return sum;
}

export function getLagrangeCoeff(_allIndexes: number[] | BN[], _myIndex: number | BN, _target: number | BN, modulus: BN) {
  const allIndexes: BN[] = _allIndexes.map((i) => new BN(i));
  const myIndex: BN = new BN(_myIndex);
  const target: BN = new BN(_target);
  let upper = new BN(1);
  let lower = new BN(1);
  for (let j = 0; j < allIndexes.length; j += 1) {
    if (myIndex.cmp(allIndexes[j]) !== 0) {
      let tempUpper = target.sub(allIndexes[j]);
      tempUpper = tempUpper.umod(modulus);
      upper = upper.mul(tempUpper);
      upper = upper.umod(modulus);
      let tempLower = myIndex.sub(allIndexes[j]);
      tempLower = tempLower.umod(modulus);
      lower = lower.mul(tempLower).umod(modulus);
    }
  }
  return upper.mul(lower.invm(modulus)).umod(modulus);
}

export function lagrangeInterpolation(shares: BN[], nodeIndex: BN[], modulus: BN) {
  if (shares.length !== nodeIndex.length) {
    return null;
  }
  let secret = new BN(0);
  for (let i = 0; i < shares.length; i += 1) {
    let upper = new BN(1);
    let lower = new BN(1);
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = upper.mul(nodeIndex[j].neg());
        upper = upper.umod(modulus);
        let temp = nodeIndex[i].sub(nodeIndex[j]);
        temp = temp.umod(modulus);
        lower = lower.mul(temp).umod(modulus);
      }
    }
    let delta = upper.mul(lower.invm(modulus)).umod(modulus);
    delta = delta.mul(shares[i]).umod(modulus);
    secret = secret.add(delta);
  }
  return secret.umod(modulus);
}
