import { Group } from "@noble/curves/abstract/curve";
import { AffinePoint } from "@noble/curves/abstract/weierstrass";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import { bigIntPointToHexPoint, bigIntUmod, generatePolynomial, getLagrangeCoeff, getShare, hexToBigInt } from "./helpers";
import { IData, IMockServer, RSSRound1Response, ServersInfo } from "./rss";
import { decrypt, encrypt, EncryptedMessage, PointHex } from "./utils";

export const toAffineHex = (affine: AffinePoint<bigint>): AffinePoint<string> => {
  return {
    x: affine.x.toString(16).padStart(64, "0"),
    y: affine.y.toString(16).padStart(64, "0"),
  };
};

export const refreshClientRound1Internal = async <T extends Group<T> & { x: bigint; y: bigint }>(params: {
  inputIndex: number;
  targetIndexes: number[];
  inputShare: bigint;
  serversInfo: ServersInfo;
  tempPubKey: Uint8Array; // uncompressed pubke
  keyType: "secp256k1" | "ed25519";
  constructPoint: (p: { x: string; y: string } | { x: bigint; y: bigint }) => T;
  nbCurve: typeof secp256k1 | typeof ed25519;
}) => {
  const { inputIndex, targetIndexes, inputShare, serversInfo, tempPubKey, nbCurve, constructPoint } = params;

  // front end also generates hierarchical secret sharing
  // - calculate lagrange coeffs
  const curveN = nbCurve.CURVE.n;
  const curveG = constructPoint({ x: nbCurve.CURVE.Gx, y: nbCurve.CURVE.Gy });

  const randomBytes = nbCurve.utils.randomPrivateKey;
  const generatePrivate = () => bigIntUmod(hexToBigInt(Buffer.from(randomBytes()).toString("hex")), curveN);

  const _L = getLagrangeCoeff([1, inputIndex], inputIndex, 0, curveN);
  const _finalLagrangeCoeffs = targetIndexes.map((target) => _L * bigIntUmod(getLagrangeCoeff([0, 1], 0, target, curveN), curveN));
  const _masterPolys = [];
  const _masterPolyCommits = [];
  const _serverPolys = [];
  const _serverPolyCommits = [];
  const generateRandomScalar = () => generatePrivate();

  for (let i = 0; i < _finalLagrangeCoeffs.length; i++) {
    const _lc = _finalLagrangeCoeffs[i];
    const _m = generatePolynomial(1, bigIntUmod(_lc * inputShare, curveN), generateRandomScalar);
    _masterPolys.push(_m);
    _masterPolyCommits.push(
      _m.map((coeff) => {
        const _gCoeff = curveG.multiply(coeff);
        return _gCoeff;
      })
    );
    const _s = generatePolynomial(serversInfo.threshold - 1, getShare(_m, 1n, curveN), generateRandomScalar);
    _serverPolys.push(_s);
    _serverPolyCommits.push(_s.map((coeff) => curveG.multiply(coeff)));
  }
  const _serverEncs = [];
  const _userEncs = [];
  for (let i = 0; i < _masterPolys.length; i++) {
    _serverEncs.push([]); // for each target_index, create an array of server encryptions
  }
  // - generate N + 1 shares
  for (let i = 0; i < targetIndexes.length; i++) {
    const _masterPoly = _masterPolys[i];
    _userEncs.push(await encrypt(Buffer.from(tempPubKey), Buffer.from(getShare(_masterPoly, 99n, curveN).toString(16).padStart(64, "0"), "hex")));

    const _serverPoly = _serverPolys[i];
    const _serverEnc: EncryptedMessage[] = _serverEncs[i];
    for (let j = 0; j < serversInfo.pubkeys.length; j++) {
      const _pub = serversInfo.pubkeys[j];
      _serverEnc.push(
        await encrypt(
          Buffer.from(`04${_pub.x.padStart(64, "0")}${_pub.y.padStart(64, "0")}`, "hex"),
          Buffer.from(
            getShare(_serverPoly, BigInt(j + 1), curveN)
              .toString(16)
              .padStart(64, "0"),
            "hex"
          )
        )
      );
    }
  }
  const _data: IData = [];
  for (let i = 0; i < targetIndexes.length; i++) {
    _data.push({
      master_poly_commits: _masterPolyCommits[i].map((pt) => {
        return { x: pt.x.toString(16).padStart(64, "0"), y: pt.y.toString(16).padStart(64, "0") };
      }),
      server_poly_commits: _serverPolyCommits[i].map((pt) => {
        return { x: pt.x.toString(16).padStart(64, "0"), y: pt.y.toString(16).padStart(64, "0") };
      }),
      target_encryptions: {
        user_enc: _userEncs[i],
        server_encs: _serverEncs[i],
      },
    });
  }
  return _data;
};

export const refreshClientRound2Internal = async <T extends Group<T> & { x: bigint; y: bigint }>(opts: {
  targetIndexes: number[];
  rssRound1Responses: RSSRound1Response[];
  serverThreshold: number;
  serverEndpoints: string[] | IMockServer[];
  factorPubs: PointHex[];
  tempPrivKey: bigint;
  dkgNewPub: PointHex;
  tssPubKey: PointHex;
  keyType: "secp256k1" | "ed25519";
  constructPoint: (p: { x: string; y: string } | { x: bigint; y: bigint }) => T;
  nbCurve: typeof secp256k1 | typeof ed25519;
}) => {
  const {
    rssRound1Responses,
    targetIndexes,
    serverThreshold,
    serverEndpoints,
    factorPubs,
    tempPrivKey,
    dkgNewPub,
    tssPubKey,
    nbCurve,
    constructPoint,
  } = opts;

  const curveN = nbCurve.CURVE.n;
  const curveG = constructPoint({ x: nbCurve.CURVE.Gx, y: nbCurve.CURVE.Gy });

  type Point = T;

  // sum up all master poly commits and sum up all server poly commits
  const sums = targetIndexes.map((_, i) => {
    for (let j = 0; j < rssRound1Responses.length; j++) {
      const rssRound1ResponseData = rssRound1Responses[j].data[i];
      const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
      if (masterPolyCommits.length !== 2) throw new Error("incorrect number of coeffs for master poly commits");
      if (serverPolyCommits.length !== serverThreshold) throw new Error("incorrect number of coeffs for server poly commits");
    }
    let sumMasterPolyCommits: Point[] = [];
    let sumServerPolyCommits: Point[] = [];

    for (let j = 0; j < rssRound1Responses.length; j++) {
      const rssRound1ResponseData = rssRound1Responses[j].data[i];
      const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
      if (sumMasterPolyCommits.length === 0 && sumServerPolyCommits.length === 0) {
        sumMasterPolyCommits = masterPolyCommits.map((p) => constructPoint(p));
        sumServerPolyCommits = serverPolyCommits.map((p) => constructPoint(p));
        continue;
      }
      sumMasterPolyCommits = sumMasterPolyCommits.map((summedCommit, k) => {
        return constructPoint(masterPolyCommits[k]).add(summedCommit);
      });
      sumServerPolyCommits = sumServerPolyCommits.map((summedCommit, k) => {
        return constructPoint(serverPolyCommits[k]).add(summedCommit);
      });
    }

    return {
      mc: sumMasterPolyCommits,
      sc: sumServerPolyCommits,
    };
  });

  // front end checks
  targetIndexes.map((target, i) => {
    const { mc, sc } = sums[i];
    // check master poly commits are consistent with tssPubKey
    const temp1 = constructPoint(dkgNewPub).multiply(getLagrangeCoeff([1, target], 1, 0, curveN));
    const temp2 = mc[0].multiply(getLagrangeCoeff([1, target], target, 0, curveN));
    const _tssPubKey = temp1.add(temp2);
    if (!_tssPubKey.equals(constructPoint(tssPubKey))) throw new Error("master poly commits inconsistent with tssPubKey");

    // check server poly commits are consistent with master poly commits
    if (!mc[0].add(mc[1]).equals(sc[0])) throw new Error("server poly commits inconsistent with master poly commits");
    return null;
  });

  // front end checks if decrypted user shares are consistent with poly commits
  const privKeyBuffer = Buffer.from(tempPrivKey.toString(16).padStart(64, "0"), "hex");
  const userShares = [];
  for (let i = 0; i < targetIndexes.length; i++) {
    const userEncs = rssRound1Responses.map((r) => r.data[i].target_encryptions.user_enc);
    const userDecs = await Promise.all(userEncs.map((encMsg) => decrypt(privKeyBuffer, encMsg)));
    const userShare = userDecs.map((userDec) => hexToBigInt(userDec.toString("hex"))).reduce((acc, d) => bigIntUmod(acc + d, curveN), BigInt(0));
    const { mc } = sums[i];
    const gU = curveG.multiply(userShare);
    const _gU = mc[0].add(mc[1].multiply(BigInt(99))); // master poly evaluated at x = 99
    if (!gU.equals(_gU)) throw new Error("decrypted user shares inconsistent with poly commits");
    userShares.push(userShare);
  }

  const userFactorEncs = await Promise.all(
    userShares.map((userShare, i) => {
      const pub = factorPubs[i];
      return encrypt(
        Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"),
        Buffer.from(userShare.toString(16).padStart(64, "0"), "hex")
      );
    })
  );

  // rearrange received serverEncs before sending them to new servers
  const serverEncs = targetIndexes.map((_, i) => {
    const serverEncsReceived = rssRound1Responses.map((r) => r.data[i].target_encryptions.server_encs);
    // flip the matrix
    const serverEncsToSend = [];
    for (let j = 0; j < serverEndpoints.length; j++) {
      const serverEnc = [];
      for (let k = 0; k < serverThreshold * 2 + 1; k++) {
        serverEnc.push(serverEncsReceived[k][j]);
      }
      serverEncsToSend.push(serverEnc);
    }

    return serverEncsToSend;
  });

  return {
    sums: sums.map((s) => ({
      mc: s.mc.map((p) => bigIntPointToHexPoint(p)),
      sc: s.sc.map((p) => bigIntPointToHexPoint(p)),
    })),
    serverEncs,
    userFactorEncs,
  };
};

export const refreshClientRound1 = async (params: {
  inputIndex: number;
  targetIndexes: number[];
  inputShare: bigint;
  serversInfo: ServersInfo;
  tempPubKey: Uint8Array; // uncompressed pubke
  keyType: "secp256k1" | "ed25519";
}) => {
  if (params.keyType === "secp256k1") {
    const constructPoint = (p: { x: string; y: string } | { x: bigint; y: bigint }) => {
      if (typeof p.x === "bigint" && typeof p.y === "bigint") {
        return secp256k1.ProjectivePoint.fromAffine({ x: p.x, y: p.y });
      } else if (typeof p.x === "string" && typeof p.y === "string") {
        return secp256k1.ProjectivePoint.fromAffine({ x: hexToBigInt(p.x), y: hexToBigInt(p.y) });
      }
      throw new Error("Invalid point");
    };
    const nbCurve = secp256k1;
    return refreshClientRound1Internal({
      ...params,
      constructPoint,
      nbCurve,
    });
  } else if (params.keyType === "ed25519") {
    const constructPoint = (p: { x: string; y: string } | { x: bigint; y: bigint }) => {
      if (typeof p.x === "bigint" && typeof p.y === "bigint") {
        return ed25519.ExtendedPoint.fromAffine({ x: p.x, y: p.y });
      } else if (typeof p.x === "string" && typeof p.y === "string") {
        return ed25519.ExtendedPoint.fromAffine({ x: hexToBigInt(p.x), y: hexToBigInt(p.y) });
      }
      throw new Error("Invalid point");
    };
    const nbCurve = ed25519;
    return refreshClientRound1Internal({
      ...params,
      constructPoint,
      nbCurve,
    });
  }
  throw new Error("Invalid key type");
};

export const refreshClientRound2 = async (opts: {
  targetIndexes: number[];
  rssRound1Responses: RSSRound1Response[];
  serverThreshold: number;
  serverEndpoints: string[] | IMockServer[];
  factorPubs: PointHex[];
  tempPrivKey: bigint;
  dkgNewPub: PointHex;
  tssPubKey: PointHex;
  keyType: "secp256k1" | "ed25519";
}) => {
  if (opts.keyType === "secp256k1") {
    const constructPoint = (p: { x: string; y: string } | { x: bigint; y: bigint }) => {
      if (typeof p.x === "bigint" && typeof p.y === "bigint") {
        return secp256k1.ProjectivePoint.fromAffine({ x: p.x, y: p.y });
      } else if (typeof p.x === "string" && typeof p.y === "string") {
        return secp256k1.ProjectivePoint.fromAffine({ x: hexToBigInt(p.x), y: hexToBigInt(p.y) });
      }
      throw new Error("Invalid point");
    };
    const nbCurve = secp256k1;
    return refreshClientRound2Internal({ ...opts, constructPoint, nbCurve });
  } else if (opts.keyType === "ed25519") {
    const constructPoint = (p: { x: string; y: string } | { x: bigint; y: bigint }) => {
      if (typeof p.x === "bigint" && typeof p.y === "bigint") {
        return ed25519.ExtendedPoint.fromAffine({ x: p.x, y: p.y });
      } else if (typeof p.x === "string" && typeof p.y === "string") {
        return ed25519.ExtendedPoint.fromAffine({ x: hexToBigInt(p.x), y: hexToBigInt(p.y) });
      }
      throw new Error("Invalid point");
    };
    const nbCurve = ed25519;
    return refreshClientRound2Internal({ ...opts, constructPoint, nbCurve });
  }
};
