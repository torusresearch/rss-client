import { CustomOptions, Data, get, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import log from "loglevel";

import {
  decrypt,
  dotProduct,
  ecCurveSecp256k1,
  ecPoint,
  encrypt,
  EncryptedMessage,
  generatePolynomial,
  getLagrangeCoeff,
  getShare,
  hexPoint,
  PointHex,
} from "./utils";

export interface IMockServer {
  get(path: string): Promise<unknown>;
  post(path: string, data?: Data): Promise<unknown>;
}

export function getEndpoint<T>(
  endpoint: string | IMockServer,
  path: string,
  options_?: RequestInit,
  customOptions?: CustomOptions
): Promise<unknown> {
  if (typeof endpoint === "string") {
    return get<T>(`${endpoint}${path}`, options_, customOptions);
  }
  return endpoint.get(path);
}

export function postEndpoint<T>(
  endpoint: string | IMockServer,
  path: string,
  data?: Data,
  options_?: RequestInit,
  customOptions?: CustomOptions
): Promise<T> {
  if (typeof endpoint === "string") {
    return post<T>(`${endpoint}${path}`, data, options_, customOptions);
  }
  return endpoint.post(path, data) as Promise<T>;
}

export type ImportOptions = {
  importKey: BN;
  newLabel: string;
  sigs: string[];
  dkgNewPub: PointHex;
  targetIndexes: number[];
  selectedServers: number[];
  factorPubs: PointHex[];
};

export type RSSClientOptions = {
  tssPubKey: PointHex;
  serverEndpoints: string[] | IMockServer[];
  serverThreshold: number;
  serverPubKeys: PointHex[];
  keyType: string;
  tempKey?: BN;
};

export type ServersInfo = {
  pubkeys: PointHex[];
  threshold: number;
  selected: number[];
};

export type RefreshOptions = {
  oldLabel: string;
  newLabel: string;
  sigs: string[];
  dkgNewPub: PointHex;
  inputShare: BN;
  inputIndex: number;
  targetIndexes: number[];
  selectedServers: number[];
  factorPubs: PointHex[];
};

export type RSSRound1ResponseData = {
  master_poly_commits: PointHex[];
  server_poly_commits: PointHex[];
  target_encryptions: {
    user_enc: EncryptedMessage;
    server_encs: EncryptedMessage[];
  };
};

export type RSSRound1Response = {
  target_index: number[];
  data: RSSRound1ResponseData[];
};

type RSSRound2ResponseData = {
  encs: EncryptedMessage[];
};

type RSSRound2Response = {
  target_index: number[];
  data: RSSRound2ResponseData[];
};

export type ServerFactorEnc = {
  data: EncryptedMessage[][];
  target_index: number[];
};

export type RefreshResponse = {
  targetIndex: number;
  factorPub: PointHex;
  serverFactorEncs: EncryptedMessage[];
  userFactorEnc: EncryptedMessage;
};

export type RecoverOptions = {
  factorKey: BN;
  serverEncs: EncryptedMessage[];
  userEnc: EncryptedMessage;
  selectedServers: number[];
  keyType: string;
};

export type RecoverResponse = {
  tssShare: BN;
};

export type IData = {
  master_poly_commits: PointHex[];
  server_poly_commits: PointHex[];
  target_encryptions: { user_enc: EncryptedMessage; server_encs: EncryptedMessage[] };
}[];

export class RSSClient {
  tssPubKey: curve.base.BasePoint;

  tempPrivKey: BN;

  tempPubKey: curve.base.BasePoint;

  serverEndpoints: string[] | IMockServer[];

  serverThreshold: number;

  serverPubKeys: PointHex[];

  ecCurve: EC;

  keyType: string;

  constructor(opts: RSSClientOptions) {
    this.keyType = opts.keyType || "secp256k1";
    this.ecCurve = new EC(this.keyType);
    this.tssPubKey = ecPoint(this.ecCurve, opts.tssPubKey);
    this.serverEndpoints = opts.serverEndpoints;
    this.serverThreshold = opts.serverThreshold;
    this.serverPubKeys = opts.serverPubKeys;
    if (opts.tempKey) {
      this.tempPrivKey = opts.tempKey;
      this.tempPubKey = ecCurveSecp256k1.g.mul(opts.tempKey);
    } else {
      const kp = ecCurveSecp256k1.genKeyPair();
      this.tempPrivKey = kp.getPrivate();
      this.tempPubKey = kp.getPublic();
    }
  }

  async import(opts: ImportOptions): Promise<RefreshResponse[]> {
    const { importKey, newLabel, sigs, dkgNewPub, targetIndexes, selectedServers, factorPubs } = opts;
    if (factorPubs.length !== targetIndexes.length) throw new Error("inconsistent factorPubs and targetIndexes lengths");
    const serversInfo: ServersInfo = {
      pubkeys: this.serverPubKeys,
      selected: selectedServers,
      threshold: this.serverThreshold,
    };

    // send requests to T servers (import only requires the T new servers)
    const rssRound1Proms = selectedServers.map((ind) => {
      const serverEndpoint = this.serverEndpoints[ind - 1];
      return postEndpoint<RSSRound1Response>(serverEndpoint, "/rss_round_1", {
        round_name: "rss_round_1",
        server_set: "new",
        server_index: ind,
        new_servers_info: serversInfo,
        user_temp_pubkey: hexPoint(this.tempPubKey),
        target_index: targetIndexes,
        auth: {
          label: newLabel, // TODO: undesigned
          sigs,
        },
        key_type: this.keyType,
      });
    });

    // front end also generates hierarchical secret sharing
    // - calculate lagrange coeffs
    const _finalLagrangeCoeffs = targetIndexes.map((target) => getLagrangeCoeff([0, 1], 0, target, this.ecCurve.n).umod(this.ecCurve.n));
    const _masterPolys = [];
    const _masterPolyCommits = [];
    const _serverPolys = [];
    const _serverPolyCommits = [];
    const generateRandomScalar = () => this.ecCurve.genKeyPair().getPrivate();
    for (let i = 0; i < _finalLagrangeCoeffs.length; i++) {
      const _lc = _finalLagrangeCoeffs[i];
      const _m = generatePolynomial(1, _lc.mul(importKey).umod(this.ecCurve.n), generateRandomScalar);
      _masterPolys.push(_m);
      _masterPolyCommits.push(
        _m.map((coeff) => {
          const _gCoeff = this.ecCurve.g.mul(coeff);
          return hexPoint(_gCoeff);
        })
      );
      const _s = generatePolynomial(serversInfo.threshold - 1, getShare(_m, 1, this.ecCurve.n), generateRandomScalar);
      _serverPolys.push(_s);
      _serverPolyCommits.push(_s.map((coeff) => hexPoint(this.ecCurve.g.mul(coeff))));
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
          Buffer.from(`04${hexPoint(this.tempPubKey).x.padStart(64, "0")}${hexPoint(this.tempPubKey).y.padStart(64, "0")}`, "hex"),
          Buffer.from(getShare(_masterPoly, 99, this.ecCurve.n).toString(16, 64), "hex")
        )
      );

      const _serverPoly = _serverPolys[i];
      const _serverEnc: EncryptedMessage[] = _serverEncs[i];
      for (let j = 0; j < serversInfo.pubkeys.length; j++) {
        const _pub = serversInfo.pubkeys[j];
        _serverEnc.push(
          await encrypt(
            Buffer.from(`04${_pub.x.padStart(64, "0")}${_pub.y.padStart(64, "0")}`, "hex"),
            Buffer.from(getShare(_serverPoly, j + 1, this.ecCurve.n).toString(16, 64), "hex")
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

    // add front end generated hierarchical sharing to the list
    rssRound1Proms.push(
      new Promise((resolve) => {
        resolve({
          target_index: targetIndexes,
          data: _data,
        });
      })
    );

    // await responses
    const rssRound1Responses = (await Promise.all(rssRound1Proms)) as RSSRound1Response[];

    // sum up all master poly commits and sum up all server poly commits
    const sums = targetIndexes.map((_, i) => {
      for (let j = 0; j < rssRound1Responses.length; j++) {
        const rssRound1ResponseData = rssRound1Responses[j].data[i];
        const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
        if (masterPolyCommits.length !== 2) throw new Error("incorrect number of coeffs for master poly commits");
        if (serverPolyCommits.length !== this.serverThreshold) throw new Error("incorrect number of coeffs for server poly commits");
      }

      let sumMasterPolyCommits: curve.base.BasePoint[] = [];
      let sumServerPolyCommits: curve.base.BasePoint[] = [];

      for (let j = 0; j < rssRound1Responses.length; j++) {
        const rssRound1ResponseData = rssRound1Responses[j].data[i];
        const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
        if (sumMasterPolyCommits.length === 0 && sumServerPolyCommits.length === 0) {
          sumMasterPolyCommits = masterPolyCommits.map((p) => ecPoint(this.ecCurve, p));
          sumServerPolyCommits = serverPolyCommits.map((p) => ecPoint(this.ecCurve, p));
          continue;
        }
        sumMasterPolyCommits = sumMasterPolyCommits.map((summedCommit, k) => {
          return ecPoint(this.ecCurve, masterPolyCommits[k]).add(summedCommit);
        });
        sumServerPolyCommits = sumServerPolyCommits.map((summedCommit, k) => {
          return ecPoint(this.ecCurve, serverPolyCommits[k]).add(summedCommit);
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
      const temp1 = ecPoint(this.ecCurve, dkgNewPub).mul(getLagrangeCoeff([1, target], 1, 0, this.ecCurve.n));
      const temp2 = mc[0].mul(getLagrangeCoeff([1, target], target, 0, this.ecCurve.n));
      const _tssPubKey = temp1.add(temp2);
      if (!_tssPubKey.eq(this.tssPubKey)) throw new Error("master poly commits inconsistent with tssPubKey");

      // check server poly commits are consistent with master poly commits
      if (!mc[0].add(mc[1]).eq(sc[0])) throw new Error("server poly commits inconsistent with master poly commits");
      return null;
    });

    // front end checks if decrypted user shares are consistent with poly commits
    const privKeyBuffer = Buffer.from(this.tempPrivKey.toString(16, 64), "hex");
    const userShares = [];
    for (let i = 0; i < targetIndexes.length; i++) {
      const userEncs = rssRound1Responses.map((r) => r.data[i].target_encryptions.user_enc);
      const userDecs = await Promise.all(userEncs.map((encMsg) => decrypt(privKeyBuffer, encMsg)));
      const userShare = userDecs.map((userDec) => new BN(userDec)).reduce((acc, d) => acc.add(d).umod(this.ecCurve.n), new BN(0));
      const { mc } = sums[i];
      const gU = this.ecCurve.g.mul(userShare);
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
      for (let j = 0; j < this.serverEndpoints.length; j++) {
        const serverEnc = [];

        // Import only has T servers and the user, so it's T + 1
        for (let k = 0; k < this.serverThreshold + 1; k++) {
          serverEnc.push(serverEncsReceived[k][j]);
        }
        serverEncsToSend.push(serverEnc);
      }

      return serverEncsToSend;
    });

    // servers sum up their shares and encrypt it for factorPubs
    const serverIndexes = this.serverEndpoints.map((_, i) => i + 1);
    const serverFactorEncs = await Promise.all(
      serverIndexes.map((ind) => {
        // TODO: specify it's "new" server set for server indexes
        const data: { master_commits: PointHex[]; server_commits: PointHex[]; server_encs: EncryptedMessage[]; factor_pubkeys: PointHex[] }[] = [];
        targetIndexes.map((_, i) => {
          const { mc, sc } = sums[i];
          const round2RequestData = {
            master_commits: mc.map(hexPoint),
            server_commits: sc.map(hexPoint),
            server_encs: serverEncs[i][ind - 1],
            factor_pubkeys: [factorPubs[i]], // TODO: must we do it like this?
          };
          data.push(round2RequestData);
          return null;
        });
        const serverEndpoint = this.serverEndpoints[ind - 1];
        return postEndpoint<RSSRound2Response>(serverEndpoint, "/rss_round_2", {
          round_name: "rss_round_2",
          server_index: ind,
          target_index: targetIndexes,
          data,
          key_type: this.keyType,
        }).catch((e) => log.error(e));
      })
    );
    if (serverFactorEncs.filter((s) => s).length < this.serverThreshold) throw new Error("not enough servers responded");

    const factorEncs: RefreshResponse[] = [];
    for (let i = 0; i < targetIndexes.length; i++) {
      factorEncs.push({
        targetIndex: targetIndexes[i],
        factorPub: factorPubs[i],
        serverFactorEncs: serverFactorEncs.map((s) => s && s.data[i].encs[0]),
        userFactorEnc: userFactorEncs[i],
      });
    }

    return factorEncs;
  }

  async refresh(opts: RefreshOptions): Promise<RefreshResponse[]> {
    const { targetIndexes, inputIndex, selectedServers, oldLabel, newLabel, sigs, dkgNewPub, inputShare, factorPubs } = opts;
    if (factorPubs.length !== targetIndexes.length) throw new Error("inconsistent factorPubs and targetIndexes lengths");
    const serversInfo: ServersInfo = {
      pubkeys: this.serverPubKeys,
      selected: selectedServers,
      threshold: this.serverThreshold,
    };

    // send requests to 2T servers
    const rssRound1Proms = selectedServers
      .map((ind) => {
        const serverEndpoint = this.serverEndpoints[ind - 1];
        return postEndpoint<RSSRound1Response>(serverEndpoint, "/rss_round_1", {
          round_name: "rss_round_1",
          server_set: "old",
          server_index: ind,
          old_servers_info: serversInfo,
          new_servers_info: serversInfo,
          old_user_share_index: inputIndex,
          user_temp_pubkey: hexPoint(this.tempPubKey),
          target_index: targetIndexes,
          auth: {
            label: oldLabel,
            sigs,
          },
          key_type: this.keyType,
        });
      })
      .concat(
        selectedServers.map((ind) => {
          const serverEndpoint = this.serverEndpoints[ind - 1];
          return postEndpoint<RSSRound1Response>(serverEndpoint, "/rss_round_1", {
            round_name: "rss_round_1",
            server_set: "new",
            server_index: ind,
            old_servers_info: serversInfo,
            new_servers_info: serversInfo,
            old_user_share_index: inputIndex,
            user_temp_pubkey: hexPoint(this.tempPubKey),
            target_index: targetIndexes,
            auth: {
              label: newLabel, // TODO: undesigned
              sigs,
            },
            key_type: this.keyType,
          });
        })
      );

    // front end also generates hierarchical secret sharing
    // - calculate lagrange coeffs
    const _L = getLagrangeCoeff([1, inputIndex], inputIndex, 0, this.ecCurve.n);
    const _finalLagrangeCoeffs = targetIndexes.map((target) => _L.mul(getLagrangeCoeff([0, 1], 0, target, this.ecCurve.n)).umod(this.ecCurve.n));
    const _masterPolys = [];
    const _masterPolyCommits = [];
    const _serverPolys = [];
    const _serverPolyCommits = [];
    const generateRandomScalar = () => this.ecCurve.genKeyPair().getPrivate();
    for (let i = 0; i < _finalLagrangeCoeffs.length; i++) {
      const _lc = _finalLagrangeCoeffs[i];
      const _m = generatePolynomial(1, _lc.mul(inputShare).umod(this.ecCurve.n), generateRandomScalar);
      _masterPolys.push(_m);
      _masterPolyCommits.push(
        _m.map((coeff) => {
          const _gCoeff = this.ecCurve.g.mul(coeff);
          return hexPoint(_gCoeff);
        })
      );
      const _s = generatePolynomial(serversInfo.threshold - 1, getShare(_m, 1, this.ecCurve.n), generateRandomScalar);
      _serverPolys.push(_s);
      _serverPolyCommits.push(_s.map((coeff) => hexPoint(this.ecCurve.g.mul(coeff))));
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
          Buffer.from(`04${hexPoint(this.tempPubKey).x.padStart(64, "0")}${hexPoint(this.tempPubKey).y.padStart(64, "0")}`, "hex"),
          Buffer.from(getShare(_masterPoly, 99, this.ecCurve.n).toString(16, 64), "hex")
        )
      );

      const _serverPoly = _serverPolys[i];
      const _serverEnc: EncryptedMessage[] = _serverEncs[i];
      for (let j = 0; j < serversInfo.pubkeys.length; j++) {
        const _pub = serversInfo.pubkeys[j];
        _serverEnc.push(
          await encrypt(
            Buffer.from(`04${_pub.x.padStart(64, "0")}${_pub.y.padStart(64, "0")}`, "hex"),
            Buffer.from(getShare(_serverPoly, j + 1, this.ecCurve.n).toString(16, 64), "hex")
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

    // add front end generated hierarchical sharing to the list
    rssRound1Proms.push(
      new Promise((resolve) => {
        resolve({
          target_index: targetIndexes,
          data: _data,
        });
      })
    );

    // await responses
    const rssRound1Responses = (await Promise.all(rssRound1Proms)) as RSSRound1Response[];

    // sum up all master poly commits and sum up all server poly commits
    const sums = targetIndexes.map((_, i) => {
      for (let j = 0; j < rssRound1Responses.length; j++) {
        const rssRound1ResponseData = rssRound1Responses[j].data[i];
        const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
        if (masterPolyCommits.length !== 2) throw new Error("incorrect number of coeffs for master poly commits");
        if (serverPolyCommits.length !== this.serverThreshold) throw new Error("incorrect number of coeffs for server poly commits");
      }

      let sumMasterPolyCommits: curve.base.BasePoint[] = [];
      let sumServerPolyCommits: curve.base.BasePoint[] = [];

      for (let j = 0; j < rssRound1Responses.length; j++) {
        const rssRound1ResponseData = rssRound1Responses[j].data[i];
        const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
        if (sumMasterPolyCommits.length === 0 && sumServerPolyCommits.length === 0) {
          sumMasterPolyCommits = masterPolyCommits.map((p) => ecPoint(this.ecCurve, p));
          sumServerPolyCommits = serverPolyCommits.map((p) => ecPoint(this.ecCurve, p));
          continue;
        }
        sumMasterPolyCommits = sumMasterPolyCommits.map((summedCommit, k) => {
          return ecPoint(this.ecCurve, masterPolyCommits[k]).add(summedCommit);
        });
        sumServerPolyCommits = sumServerPolyCommits.map((summedCommit, k) => {
          return ecPoint(this.ecCurve, serverPolyCommits[k]).add(summedCommit);
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
      const temp1 = ecPoint(this.ecCurve, dkgNewPub).mul(getLagrangeCoeff([1, target], 1, 0, this.ecCurve.n));
      const temp2 = mc[0].mul(getLagrangeCoeff([1, target], target, 0, this.ecCurve.n));
      const _tssPubKey = temp1.add(temp2);
      if (!_tssPubKey.eq(this.tssPubKey)) throw new Error("master poly commits inconsistent with tssPubKey");

      // check server poly commits are consistent with master poly commits
      if (!mc[0].add(mc[1]).eq(sc[0])) throw new Error("server poly commits inconsistent with master poly commits");
      return null;
    });

    // front end checks if decrypted user shares are consistent with poly commits
    const privKeyBuffer = Buffer.from(this.tempPrivKey.toString(16, 64), "hex");
    const userShares = [];
    for (let i = 0; i < targetIndexes.length; i++) {
      const userEncs = rssRound1Responses.map((r) => r.data[i].target_encryptions.user_enc);
      const userDecs = await Promise.all(userEncs.map((encMsg) => decrypt(privKeyBuffer, encMsg)));
      const userShare = userDecs.map((userDec) => new BN(userDec)).reduce((acc, d) => acc.add(d).umod(this.ecCurve.n), new BN(0));
      const { mc } = sums[i];
      const gU = this.ecCurve.g.mul(userShare);
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
      for (let j = 0; j < this.serverEndpoints.length; j++) {
        const serverEnc = [];
        for (let k = 0; k < this.serverThreshold * 2 + 1; k++) {
          serverEnc.push(serverEncsReceived[k][j]);
        }
        serverEncsToSend.push(serverEnc);
      }

      return serverEncsToSend;
    });

    // servers sum up their shares and encrypt it for factorPubs
    const serverIndexes = this.serverEndpoints.map((_, i) => i + 1);
    const serverFactorEncs = await Promise.all(
      serverIndexes.map((ind) => {
        // TODO: specify it's "new" server set for server indexes
        const data: { master_commits: PointHex[]; server_commits: PointHex[]; server_encs: EncryptedMessage[]; factor_pubkeys: PointHex[] }[] = [];
        targetIndexes.map((_, i) => {
          const { mc, sc } = sums[i];
          const round2RequestData = {
            master_commits: mc.map(hexPoint),
            server_commits: sc.map(hexPoint),
            server_encs: serverEncs[i][ind - 1],
            factor_pubkeys: [factorPubs[i]], // TODO: must we do it like this?
          };
          data.push(round2RequestData);
          return null;
        });
        const serverEndpoint = this.serverEndpoints[ind - 1];
        return postEndpoint<RSSRound2Response>(serverEndpoint, "/rss_round_2", {
          round_name: "rss_round_2",
          server_index: ind,
          target_index: targetIndexes,
          data,
          key_type: this.keyType,
        }).catch((e) => log.error(e));
      })
    );
    if (serverFactorEncs.filter((s) => s).length < this.serverThreshold) throw new Error("not enough servers responded");

    const factorEncs: RefreshResponse[] = [];
    for (let i = 0; i < targetIndexes.length; i++) {
      factorEncs.push({
        targetIndex: targetIndexes[i],
        factorPub: factorPubs[i],
        serverFactorEncs: serverFactorEncs.map((s) => s && s.data[i].encs[0]),
        userFactorEnc: userFactorEncs[i],
      });
    }

    return factorEncs;
  }
}

export async function recover(opts: RecoverOptions): Promise<RecoverResponse> {
  const { factorKey, serverEncs, userEnc, selectedServers, keyType } = opts;
  const ecCurve = new EC(keyType || "secp256k1");
  const factorKeyBuf = Buffer.from(factorKey.toString(16, 64), "hex");
  const prom1 = decrypt(factorKeyBuf, userEnc).then((buf) => new BN(buf));
  const prom2 = Promise.all(serverEncs.map((serverEnc) => serverEnc && decrypt(factorKeyBuf, serverEnc).then((buf) => new BN(buf))));
  const [decryptedUserEnc, decryptedServerEncs] = await Promise.all([prom1, prom2]);
  // use threshold number of factor encryptions from the servers to interpolate server share
  const someDecrypted = decryptedServerEncs.filter((_, j) => selectedServers.indexOf(j + 1) >= 0);
  const decryptedLCs = selectedServers.map((index) => getLagrangeCoeff(selectedServers, index, 0, ecCurve.n));
  const temp1 = decryptedUserEnc.mul(getLagrangeCoeff([1, 99], 99, 0, ecCurve.n));
  const serverReconstructed = dotProduct(someDecrypted, decryptedLCs).umod(ecCurve.n);
  const temp2 = serverReconstructed.mul(getLagrangeCoeff([1, 99], 1, 0, ecCurve.n));
  const tssShare = temp1.add(temp2).umod(ecCurve.n);

  return { tssShare };
}
