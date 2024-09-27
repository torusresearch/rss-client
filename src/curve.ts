import { AffinePoint, Group } from "@noble/curves/abstract/curve";
import { ExtPointType } from "@noble/curves/abstract/edwards";
import { Hex } from "@noble/curves/abstract/utils";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import { hexToBigInt } from "./utils";

export type KeyType = "secp256k1" | "ed25519";

export type AffineHex = AffinePoint<string>;

export type AffineBigInt = AffinePoint<bigint>;

export type BasePoint = ProjPointType<bigint> | ExtPointType;

// TODO: check on z and t
export function toAffineBigInt(affine: AffineHex): AffineBigInt {
  return { x: hexToBigInt(affine.x), y: hexToBigInt(affine.y) };
}

export function toPoint(affine: AffineBigInt, keyType: KeyType): Group<BasePoint> {
  if (keyType === "secp256k1") {
    return secp256k1.ProjectivePoint.fromAffine(affine);
  }
  return ed25519.ExtendedPoint.fromAffine(affine);
}

export function toGroupPoint(point: BasePoint): Group<BasePoint> {
  return point as Group<BasePoint>;
}

export class CurveSelector {
  keyType: KeyType;

  n: bigint;

  constructor(opts: { keyType: KeyType }) {
    this.keyType = opts.keyType;
    this.n = this.keyType === "secp256k1" ? secp256k1.CURVE.n : ed25519.CURVE.n;
  }

  getPublicKey(key: Hex, compressed = true) {
    return this.keyType === "secp256k1" ? secp256k1.getPublicKey(key, compressed) : ed25519.getPublicKey(key);
  }

  generatePrivateKey() {
    return this.keyType === "secp256k1" ? secp256k1.utils.randomPrivateKey() : ed25519.utils.randomPrivateKey();
  }
}
