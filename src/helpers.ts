export function hexToBigInt(hex: string): bigint {
  // Ensure the hex string starts with '0x'
  const hexWithPrefix = hex.startsWith("0x") ? hex : `0x${hex}`;
  return BigInt(hexWithPrefix);
}

export function bufferToBigInt(buffer: Buffer): bigint {
  return hexToBigInt(buffer.toString("hex"));
}

export function bigIntUmod(a: bigint, m: bigint): bigint {
  // return a % m;
  return ((a % m) + m) % m;
}

export function bigIntPointToHexPoint(point: { x: bigint; y: bigint }) {
  return {
    x: point.x.toString(16).padStart(64, "0"),
    y: point.y.toString(16).padStart(64, "0"),
  };
}

// You'll also need to implement a modular inverse function for BigInt
export function modularInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m];
  let [old_s, s] = [BigInt(1), BigInt(0)];
  let [old_t, t] = [BigInt(0), BigInt(1)];

  while (r !== BigInt(0)) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
    [old_t, t] = [t, old_t - quotient * t];
  }

  if (old_r > BigInt(1)) {
    throw new Error("Modular inverse does not exist");
  }

  if (old_s < BigInt(0)) {
    old_s += m;
  }

  return old_s;
}

export function generatePolynomial(degree: number, yIntercept: bigint, randomElement: () => bigint): bigint[] {
  const res: bigint[] = [];
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

export function getShare(polynomial: bigint[], index: bigint, modulus: bigint) {
  let res = BigInt(0);
  for (let i = 0; i < polynomial.length; i++) {
    const term = polynomial[i] * index ** BigInt(i);
    res = bigIntUmod(term, modulus) + res;
  }
  return bigIntUmod(res, modulus);
}

export function dotProduct(arr1: bigint[], arr2: bigint[], modulus?: bigint) {
  if (arr1.length !== arr2.length) {
    throw new Error("arrays of different lengths");
  }
  let sum = BigInt(0);
  for (let i = 0; i < arr1.length; i++) {
    // eslint-disable-next-line prettier/prettier
    sum = sum + ( arr1[i] * arr2[i] );
    if (modulus) {
      sum = bigIntUmod(sum, modulus);
    }
  }
  return sum;
}

export function getLagrangeCoeff(_allIndexes: number[] | bigint[], _myIndex: number | bigint, _target: number | bigint, modulus: bigint) {
  const allIndexes: bigint[] = _allIndexes.map((i) => BigInt(i));
  const myIndex: bigint = BigInt(_myIndex);
  const target: bigint = BigInt(_target);
  let upper = BigInt(1);
  let lower = BigInt(1);

  for (let j = 0; j < allIndexes.length; j += 1) {
    if (myIndex !== allIndexes[j]) {
      let tempUpper = target - allIndexes[j];
      tempUpper = bigIntUmod(tempUpper, modulus);
      upper = upper * tempUpper;
      upper = bigIntUmod(upper, modulus);
      let tempLower = myIndex - allIndexes[j];
      tempLower = bigIntUmod(tempLower, modulus);
      lower = bigIntUmod(lower * tempLower, modulus);
    }
  }
  return bigIntUmod(upper * modularInverse(lower, modulus), modulus);
}

export function lagrangeInterpolation(shares: bigint[], nodeIndex: bigint[], modulus: bigint) {
  if (shares.length !== nodeIndex.length) {
    return null;
  }
  let secret = BigInt(0);
  for (let i = 0; i < shares.length; i += 1) {
    let upper = BigInt(1);
    let lower = BigInt(1);
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = bigIntUmod(upper * BigInt(-1) * nodeIndex[j], modulus);
        const temp = bigIntUmod(nodeIndex[i] - nodeIndex[j], modulus);
        lower = bigIntUmod(lower * temp, modulus);
      }
    }
    let delta = bigIntUmod(upper * modularInverse(lower, modulus), modulus);
    delta = bigIntUmod(delta * shares[i], modulus);
    secret = bigIntUmod(secret + delta, modulus);
  }
  return secret;
}
