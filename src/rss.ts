import { generatePrivate } from "@toruslabs/eccrypto";
import axios from "axios";
import BN from "bn.js";
import { ec as EC } from "elliptic";

import { decrypt, ecPoint, encrypt, generatePolynomial, getLagrangeCoeffs, getShare, hexPoint } from "./utils";

const ec = new EC("secp256k1");
export const ecCurve = ec;

export type PointHex = {
  x: string | null;
  y: string | null;
};

export type RSSClientOptions = {
  tssPubKey: PointHex;
  serverEndpoints: string[];
  serverThreshold: number;
  serverPubKeys: PointHex[];
  tempKey?: BN;
};

export type ServersInfo = {
  pubkeys: PointHex[];
  threshold: number;
  selected: number[];
};

export type RefreshOptions = {
  vid1: string;
  vid2: string;
  vidSigs: any[];
  dkg2Pub: PointHex;
  inputShare: BN;
  inputIndex: number;
  targetIndexes: number[];
  selectedServers: number[];
};

export class RSSClient {
  tssPubKey: PointHex;

  factorPubs: PointHex[];

  tempPrivKey: BN;

  tempPubKey: PointHex;

  serverEndpoints: string[];

  serverThreshold: number;

  serverPubKeys: PointHex[];

  constructor(opts: RSSClientOptions) {
    this.tssPubKey = opts.tssPubKey;
    this.serverEndpoints = opts.serverEndpoints;
    this.serverThreshold = opts.serverThreshold;
    this.serverPubKeys = opts.serverPubKeys;
    if (opts.tempKey) {
      this.tempPrivKey = opts.tempKey;
      this.tempPubKey = ecCurve.g.mul(opts.tempKey);
    } else {
      const tempPrivKey = new BN(generatePrivate());
      this.tempPubKey = ecCurve.g.mul(tempPrivKey);
    }
  }

  async refresh(opts: RefreshOptions): Promise<{ serverFactorEncs; userFactorEncs }> {
    const { targetIndexes, inputIndex, selectedServers, vid1, vid2, vidSigs, dkg2Pub, inputShare } = opts;
    const serversInfo: ServersInfo = {
      pubkeys: this.serverPubKeys,
      selected: selectedServers,
      threshold: this.serverThreshold,
    };

    // send requests to 2T servers
    const rssRound1Proms = selectedServers
      .map((ind) => {
        const serverEndpoint = this.serverEndpoints[ind - 1];
        return axios
          .post(`${serverEndpoint}/rss_round_1`, {
            round_name: "rss_round_1",
            server_set: "old",
            server_index: ind,
            old_servers_info: serversInfo,
            new_servers_info: serversInfo,
            old_user_share_index: inputIndex,
            user_temp_pubkey: hexPoint(this.tempPubKey),
            target_index: targetIndexes,
            auth: {
              vid1,
              vidSigs,
            },
          })
          .then((a) => a.data);
      })
      .concat(
        selectedServers.map((ind) => {
          const serverEndpoint = this.serverEndpoints[ind - 1];
          return axios
            .post(`${serverEndpoint}/rss_round_1`, {
              round_name: "rss_round_1",
              server_set: "new",
              server_index: ind,
              old_servers_info: serversInfo,
              new_servers_info: serversInfo,
              old_user_share_index: inputIndex,
              user_temp_pubkey: hexPoint(this.tempPubKey),
              target_index: targetIndexes,
              auth: {
                vid2, // TODO: undesigned
                vidSigs,
              },
            })
            .then((a) => a.data);
        })
      );

    // front end also generates hierarchical secret sharing
    // - calculate lagrange coeffs
    const _L = getLagrangeCoeffs([1, inputIndex], inputIndex);
    const _finalLagrangeCoeffs = targetIndexes.map((target) => _L.mul(getLagrangeCoeffs([0, 1], 0, target)).umod(ecCurve.n));
    const _masterPolys = [];
    const _masterPolyCommits = [];
    const _serverPolys = [];
    const _serverPolyCommits = [];
    for (let i = 0; i < _finalLagrangeCoeffs.length; i++) {
      const _lc = _finalLagrangeCoeffs[i];
      const _m = generatePolynomial(1, _lc.mul(inputShare).umod(ecCurve.n));
      _masterPolys.push(_m);
      _masterPolyCommits.push(
        _m.map((coeff) => {
          const _gCoeff = ecCurve.g.mul(coeff);
          return hexPoint(_gCoeff);
        })
      );
      const _s = generatePolynomial(serversInfo.threshold - 1, getShare(_m, 1));
      _serverPolys.push(_s);
      _serverPolyCommits.push(_s.map((coeff) => hexPoint(ecCurve.g.mul(coeff))));
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
          Buffer.from(getShare(_masterPoly, 2).toString(16, 64), "hex")
        )
      );

      const _serverPoly = _serverPolys[i];
      const _serverEnc = _serverEncs[i];
      for (let j = 0; j < serversInfo.pubkeys.length; j++) {
        const _pub = serversInfo.pubkeys[j];
        _serverEnc.push(
          await encrypt(
            Buffer.from(`04${_pub.x.padStart(64, "0")}${_pub.y.padStart(64, "0")}`, "hex"),
            Buffer.from(getShare(_serverPoly, j + 1).toString(16, 64), "hex")
          )
        );
      }
    }
    const _data = [];
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
          targetIndexes,
          data: _data,
        });
      })
    );

    // await responses
    const rssRound1Responses = await Promise.all(rssRound1Proms);

    // sum up all master poly commits and sum up all server poly commits
    const sums = targetIndexes.map((_, i) => {
      for (let j = 0; j < rssRound1Responses.length; j++) {
        const rssRound1ResponseData = rssRound1Responses[j].data[i];
        const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
        if (masterPolyCommits.length !== 2) throw new Error("incorrect number of coeffs for master poly commits");
        if (serverPolyCommits.length !== this.serverThreshold) throw new Error("incorrect number of coeffs for server poly commits");
      }

      let sumMasterPolyCommits = [];
      let sumServerPolyCommits = [];

      for (let j = 0; j < rssRound1Responses.length; j++) {
        const rssRound1ResponseData = rssRound1Responses[j].data[i];
        const { master_poly_commits: masterPolyCommits, server_poly_commits: serverPolyCommits } = rssRound1ResponseData;
        if (sumMasterPolyCommits.length === 0 && sumServerPolyCommits.length === 0) {
          sumMasterPolyCommits = masterPolyCommits.map(ecPoint);
          sumServerPolyCommits = serverPolyCommits.map(ecPoint);
          continue;
        }
        sumMasterPolyCommits = sumMasterPolyCommits.map((summedCommit, k) => {
          return ecPoint(masterPolyCommits[k]).add(summedCommit);
        });
        sumServerPolyCommits = sumServerPolyCommits.map((summedCommit, k) => {
          return ecPoint(serverPolyCommits[k]).add(summedCommit);
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
      const temp1 = ecPoint(dkg2Pub).mul(getLagrangeCoeffs([1, target], 1));
      const temp2 = mc[0].mul(getLagrangeCoeffs([1, target], target));
      const _tssPubKey = temp1.add(temp2);
      if (
        _tssPubKey.x.toString(16, 64) !== ecPoint(this.tssPubKey).x.toString(16, 64) ||
        _tssPubKey.y.toString(16, 64) !== ecPoint(this.tssPubKey).y.toString(16, 64)
      )
        throw new Error("master poly commits inconsistent with tssPubKey");

      // check server poly commits are consistent with master poly commits
      if (mc[0].add(mc[1]).x.toString(16, 64) !== sc[0].x.toString(16, 64) || mc[0].add(mc[1]).y.toString(16, 64) !== sc[0].y.toString(16, 64))
        throw new Error("server poly commits inconsistent with master poly commits");
      return null;
    });

    // front end checks if decrypted user shares are consistent with poly commits
    const privKeyBuffer = Buffer.from(this.tempPrivKey.toString(16, 64), "hex");
    const userShares = [];
    for (let i = 0; i < targetIndexes.length; i++) {
      const userEncs = rssRound1Responses.map((r) => r.data[i].target_encryptions.user_enc);
      const userDecs = await Promise.all(userEncs.map((encMsg) => decrypt(privKeyBuffer, encMsg)));
      const userShare = userDecs.map((userDec) => new BN(userDec)).reduce((acc, d) => acc.add(d).umod(ecCurve.n), new BN(0));
      const { mc } = sums[i];
      const gU = ecCurve.g.mul(userShare);
      const _gU = mc[0].add(mc[1].mul(new BN(2))); // master poly evaluated at x = 2
      if (gU.x.toString(16, 64) !== _gU.x.toString(16, 64) || gU.y.toString(16, 64) !== _gU.y.toString(16, 64))
        throw new Error("decrypted user shares inconsistent with poly commits");
      userShares.push(userShare);
    }

    const userFactorEncs = await Promise.all(
      userShares.map((userShare, i) => {
        const pub = this.factorPubs[i];
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
        const data = [];
        targetIndexes.map((_, i) => {
          const { mc, sc } = sums[i];
          const round2RequestData = {
            master_commits: mc.map(hexPoint),
            server_commits: sc.map(hexPoint),
            server_encs: serverEncs[i][ind - 1],
            factor_pubkeys: [this.factorPubs[i]], // TODO: must we do it like this?
          };
          data.push(round2RequestData);
          return null;
        });
        const serverEndpoint = this.serverEndpoints[ind - 1];
        return axios
          .post(`${serverEndpoint}/rss_round_2`, {
            round_name: "rss_round_2",
            server_index: ind,
            target_index: targetIndexes,
            data,
          })
          .then((a) => a.data);
      })
    );

    return {
      serverFactorEncs,
      userFactorEncs,
    };
  }
}
