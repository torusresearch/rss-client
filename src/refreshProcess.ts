import BN from "bn.js";
import { curve, ec as EC } from "elliptic";

import { IData, IMockServer, RSSRound1Response, ServersInfo } from "./rss";
import { decrypt, ecPoint, encrypt, EncryptedMessage, generatePolynomial, getLagrangeCoeff, getShare, hexPoint, PointHex } from "./utils";

export const refreshClientRound1 = async (params: {
  inputIndex: number;
  targetIndexes: number[];
  inputShare: BN;
  serversInfo: ServersInfo;
  tempPubKey: PointHex;
  keyType: "secp256k1" | "ed25519";
}) => {
  const { inputIndex, targetIndexes, inputShare, serversInfo, tempPubKey, keyType } = params;

  // front end also generates hierarchical secret sharing
  // - calculate lagrange coeffs

  const ecCurve = new EC(keyType);
  const curveN = ecCurve.n;

  const curveG = ecCurve.g;

  const generatePrivate = () => ecCurve.genKeyPair().getPrivate();

  const _L = getLagrangeCoeff([1, inputIndex], inputIndex, 0, curveN);
  const _finalLagrangeCoeffs = targetIndexes.map((target) => _L.mul(getLagrangeCoeff([0, 1], 0, target, curveN)).umod(curveN));
  const _masterPolys = [];
  const _masterPolyCommits = [];
  const _serverPolys = [];
  const _serverPolyCommits = [];
  const generateRandomScalar = () => generatePrivate();

  for (let i = 0; i < _finalLagrangeCoeffs.length; i++) {
    const _lc = _finalLagrangeCoeffs[i];
    const _m = generatePolynomial(1, _lc.mul(inputShare).umod(curveN), generateRandomScalar);
    _masterPolys.push(_m);
    _masterPolyCommits.push(
      _m.map((coeff) => {
        const _gCoeff = curveG.mul(coeff);
        return hexPoint(_gCoeff);
      })
    );
    const _s = generatePolynomial(serversInfo.threshold - 1, getShare(_m, 1, curveN), generateRandomScalar);
    _serverPolys.push(_s);
    _serverPolyCommits.push(_s.map((coeff) => hexPoint(curveG.mul(coeff))));
  }
  const _serverEncs = [];
  const _userEncs = [];
  for (let i = 0; i < _masterPolys.length; i++) {
    _serverEncs.push([]); // for each target_index, create an array of server encryptions
  }
  // - generate N + 1 shares
  for (let i = 0; i < targetIndexes.length; i++) {
    const _masterPoly = _masterPolys[i];
    _userEncs.push(
      await encrypt(
        Buffer.from(`04${tempPubKey.x.padStart(64, "0")}${tempPubKey.y.padStart(64, "0")}`, "hex"),
        Buffer.from(getShare(_masterPoly, 99, curveN).toString(16, 64), "hex")
      )
    );

    const _serverPoly = _serverPolys[i];
    const _serverEnc: EncryptedMessage[] = _serverEncs[i];
    for (let j = 0; j < serversInfo.pubkeys.length; j++) {
      const _pub = serversInfo.pubkeys[j];
      _serverEnc.push(
        await encrypt(
          Buffer.from(`04${_pub.x.padStart(64, "0")}${_pub.y.padStart(64, "0")}`, "hex"),
          Buffer.from(getShare(_serverPoly, j + 1, curveN).toString(16, 64), "hex")
        )
      );
    }
  }
  const _data: IData = [];
  for (let i = 0; i < targetIndexes.length; i++) {
    _data.push({
      master_poly_commits: _masterPolyCommits[i],
      server_poly_commits: _serverPolyCommits[i],
      target_encryptions: {
        user_enc: _userEncs[i],
        server_encs: _serverEncs[i],
      },
    });
  }
  return _data;
};

export const refreshClientRound2 = async (opts: {
  targetIndexes: number[];
  rssRound1Responses: RSSRound1Response[];
  serverThreshold: number;
  serverEndpoints: string[] | IMockServer[];
  factorPubs: PointHex[];
  tempPrivKey: BN;
  dkgNewPub: PointHex;
  tssPubKey: PointHex;
  keyType: "secp256k1" | "ed25519";
}) => {
  const { rssRound1Responses, targetIndexes, serverThreshold, serverEndpoints, factorPubs, tempPrivKey, dkgNewPub, tssPubKey, keyType } = opts;

  const ecCurve = new EC(keyType);
  const curveN = ecCurve.n;

  // sum up all master poly commits and sum up all server poly commits
  const sums = targetIndexes.map((_, i) => {
    for (let j = 0; j < rssRound1Responses.length; j++) {
      const rssRound1ResponseData = rssRound1Responses[j].data[i];
      const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
      if (masterPolyCommits.length !== 2) throw new Error("incorrect number of coeffs for master poly commits");
      if (serverPolyCommits.length !== serverThreshold) throw new Error("incorrect number of coeffs for server poly commits");
    }

    let sumMasterPolyCommits: curve.base.BasePoint[] = [];
    let sumServerPolyCommits: curve.base.BasePoint[] = [];

    for (let j = 0; j < rssRound1Responses.length; j++) {
      const rssRound1ResponseData = rssRound1Responses[j].data[i];
      const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
      if (sumMasterPolyCommits.length === 0 && sumServerPolyCommits.length === 0) {
        sumMasterPolyCommits = masterPolyCommits.map((p) => ecPoint(ecCurve, p));
        sumServerPolyCommits = serverPolyCommits.map((p) => ecPoint(ecCurve, p));
        continue;
      }
      sumMasterPolyCommits = sumMasterPolyCommits.map((summedCommit, k) => {
        return ecPoint(ecCurve, masterPolyCommits[k]).add(summedCommit);
      });
      sumServerPolyCommits = sumServerPolyCommits.map((summedCommit, k) => {
        return ecPoint(ecCurve, serverPolyCommits[k]).add(summedCommit);
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
    const temp1 = ecPoint(ecCurve, dkgNewPub).mul(getLagrangeCoeff([1, target], 1, 0, curveN));
    const temp2 = mc[0].mul(getLagrangeCoeff([1, target], target, 0, curveN));
    const _tssPubKey = temp1.add(temp2);
    if (!_tssPubKey.eq(ecPoint(ecCurve, tssPubKey))) throw new Error("master poly commits inconsistent with tssPubKey");

    // check server poly commits are consistent with master poly commits
    if (!mc[0].add(mc[1]).eq(sc[0])) throw new Error("server poly commits inconsistent with master poly commits");
    return null;
  });

  // front end checks if decrypted user shares are consistent with poly commits
  const privKeyBuffer = Buffer.from(tempPrivKey.toString(16, 64), "hex");
  const userShares = [];
  for (let i = 0; i < targetIndexes.length; i++) {
    const userEncs = rssRound1Responses.map((r) => r.data[i].target_encryptions.user_enc);
    const userDecs = await Promise.all(userEncs.map((encMsg) => decrypt(privKeyBuffer, encMsg)));
    const userShare = userDecs.map((userDec) => new BN(userDec)).reduce((acc, d) => acc.add(d).umod(curveN), new BN(0));
    const { mc } = sums[i];
    const gU = ecCurve.g.mul(userShare);
    const _gU = mc[0].add(mc[1].mul(new BN(99))); // master poly evaluated at x = 99
    if (!gU.eq(_gU)) throw new Error("decrypted user shares inconsistent with poly commits");
    userShares.push(userShare);
  }

  const userFactorEncs = await Promise.all(
    userShares.map((userShare, i) => {
      const pub = factorPubs[i];
      return encrypt(Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"), Buffer.from(userShare.toString(16, 64), "hex"));
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

  return { sums, serverEncs, userFactorEncs };
};
