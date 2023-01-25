/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-loop-func */
import BN from "bn.js";

import { ServersInfo } from "./rss";
import { ecCurve, encrypt, EncryptedMessage, generatePolynomial, getLagrangeCoeffs, getShare, hexPoint, PointHex } from "./utils";

type AuthData = {
  label: string;
  sigs: string[];
};

type RSSRound1Request = {
  round_name: string;
  server_set: string;
  server_index: number;
  old_servers_info: ServersInfo;
  new_servers_info: ServersInfo;
  old_user_share_index: number;
  user_temp_pubkey: PointHex;
  target_index: number[];
  auth: unknown;
};

type RSSRound1ResponseData = {
  master_poly_commits: PointHex[];
  server_poly_commits: PointHex[];
  target_encryptions: {
    user_enc: EncryptedMessage;
    server_encs: EncryptedMessage[];
  };
};

type RSSRound1Response = {
  target_index: number[];
  data: RSSRound1ResponseData[];
};

type RSSRound2RequestData = {
  master_commits: PointHex[];
  server_commits: PointHex[];
  server_encs: EncryptedMessage[];
  factor_pubkeys: PointHex[];
};

type RSSRound2Request = {
  round_name: string;
  server_index: number;
  target_index: number[];
  data: RSSRound2RequestData[];
};

type RSSRound2ResponseData = {
  encs: EncryptedMessage[];
};

type RSSRound2Response = {
  target_index: number[];
  data: RSSRound2ResponseData[];
};

export class MockServer {
  pubKey: PointHex;

  shareDB: {
    [label: string]: BN;
  };

  store: {
    [key: string]: string;
  };

  tssNonce: {
    [vidAndTSSTag: string]: number;
  };

  constructor(pubKey: PointHex) {
    this.pubKey = pubKey;
    this.shareDB = {};
    this.store = {};
    this.tssNonce = {};
  }

  async getTSSShare(label: string): Promise<BN> {
    return this.shareDB[label];
  }

  async get<T>(path: string): Promise<T> {
    if (path === "/public_key") {
      return this.pubKey as T;
    }
    throw new Error(`unknown get path ${path}`);
  }

  async post<T>(path: string, data: any): Promise<T> {
    const { label, tss_share_hex: tssShareHex } = data;
    if (path === "/tss_share") {
      this.shareDB[label] = new BN(tssShareHex.padStart(64, "0"), "hex");
      return {} as T;
    }
    if (path === "/private_key") {
      const privKey = data.private_key;
      this.store.privKey = privKey;
      return {} as T;
    }
    if (path === "/get_tss_nonce") {
      const { vid, tssTag } = data;
      return { tss_nonce: this.tssNonce[`${vid}\u0015${tssTag}`] } as T;
    }
    if (path === "/set_tss_nonce") {
      const { vid, tssTag, tssNonce } = data;
      this.tssNonce[`${vid}\u0015${tssTag}`] = tssNonce;
      return {} as T;
    }
    throw new Error(`unknown post path ${path}`);
  }

  async RSSRound1Handler(body: RSSRound1Request): Promise<RSSRound1Response> {
    const b = body;
    const auth = b.auth as AuthData;
    // TODO: verify vid (unique label verifierName + verifierID) against vid_sigs (signature from servers on vid)

    if (b.round_name !== "rss_round_1") throw new Error("incorrect round name");
    if (b.server_set !== "old" && b.server_set !== "new") throw new Error("server set must be either 'old' or 'new'");
    // only allow target indexes of 2, 3 for the refresh
    if (!Array.isArray(b.target_index) || b.target_index.filter((elem) => elem !== 2 && elem !== 3).length > 0) {
      throw new Error("invalid target index, only 2, 3 allowed");
    }
    if (b.old_user_share_index !== 2 && b.old_user_share_index !== 3) {
      throw new Error("invalid index for user share");
    }

    let serversInfo: ServersInfo;
    if (b.server_set === "old") {
      serversInfo = b.old_servers_info;
    } else {
      serversInfo = b.new_servers_info;
    }

    // TODO: check old and new server pubkeys independently, against the registered node list
    // TODO: check server_index independently, against the registered node list

    if (b.server_index <= 0 || b.server_index > serversInfo.pubkeys.length) throw new Error("server index out of bounds");
    if (serversInfo.selected.filter((selectedIndex) => selectedIndex <= 0 || b.server_index > serversInfo.pubkeys.length).length > 0)
      throw new Error("selected indexes out of bounds");
    if (serversInfo.selected.indexOf(b.server_index) === -1) throw new Error("unselected server, should not have received rss round 1 message");

    // calculate appropriate lagrange coefficients
    let finalLagrangeCoeffs;
    if (b.server_set === "old") {
      // firstly, calculate lagrange coefficient for own server sharing poly
      let L = getLagrangeCoeffs(serversInfo.selected, b.server_index, 0);
      // secondly, calculate lagrange coefficient for master sharing poly
      L = L.mul(getLagrangeCoeffs([1, b.old_user_share_index], 1, 0)).umod(ecCurve.n);
      // thirdly, calculate lagrange coefficient for new master sharing poly
      finalLagrangeCoeffs = b.target_index.map((target) => L.mul(getLagrangeCoeffs([0, 1], 0, target)).umod(ecCurve.n));
    } else {
      // firstly, calculate lagrange coefficient for own server sharing poly
      const L = getLagrangeCoeffs(serversInfo.selected, b.server_index, 0);
      // secondly, calculate lagrange coefficient for master sharing poly
      finalLagrangeCoeffs = b.target_index.map((target) => L.mul(getLagrangeCoeffs([0, 1], 1, target)).umod(ecCurve.n));
    }

    // retrieve server tss subshare from db
    const tssServerShare = await this.getTSSShare(auth.label);

    const masterPolys = [];
    const masterPolyCommits = [];
    const serverPolys = [];
    const serverPolyCommits = [];

    for (let i = 0; i < finalLagrangeCoeffs.length; i++) {
      const lc = finalLagrangeCoeffs[i];
      const m = generatePolynomial(1, lc.mul(tssServerShare).umod(ecCurve.n));
      masterPolys.push(m);
      masterPolyCommits.push(
        m.map((coeff) => {
          const gCoeff = ecCurve.g.mul(coeff);
          return hexPoint(gCoeff);
        })
      );
      const s = generatePolynomial(b.new_servers_info.threshold - 1, getShare(m, 1));
      serverPolys.push(s);
      serverPolyCommits.push(s.map((coeff) => hexPoint(ecCurve.g.mul(coeff))));
    }

    const serverEncs: EncryptedMessage[][] = [];
    const userEncs: EncryptedMessage[] = [];
    for (let i = 0; i < masterPolys.length; i++) {
      serverEncs.push([]); // for each target_index, create an array of server encryptions
    }

    // generate N + 1 shares
    for (let i = 0; i < b.target_index.length; i++) {
      const masterPoly = masterPolys[i];
      userEncs.push(
        await encrypt(
          Buffer.from(`04${b.user_temp_pubkey.x.padStart(64, "0")}${b.user_temp_pubkey.y.padStart(64, "0")}`, "hex"),
          Buffer.from(getShare(masterPoly, 2).toString(16, 64), "hex")
        )
      );

      const serverPoly = serverPolys[i];
      const serverEnc = serverEncs[i];
      for (let j = 0; j < b.new_servers_info.pubkeys.length; j++) {
        const pub = b.new_servers_info.pubkeys[j];
        serverEnc.push(
          await encrypt(
            Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"),
            Buffer.from(getShare(serverPoly, j + 1).toString(16, 64), "hex")
          )
        );
      }
    }

    const data: RSSRound1ResponseData[] = [];

    for (let i = 0; i < b.target_index.length; i++) {
      data.push({
        master_poly_commits: masterPolyCommits[i],
        server_poly_commits: serverPolyCommits[i],
        target_encryptions: {
          user_enc: userEncs[i],
          server_encs: serverEncs[i],
        },
      });
    }

    const resp: RSSRound1Response = {
      target_index: b.target_index,
      data,
    };

    return resp;
  }

  // async RSSRound2Handler(body: RSSRound2Request): Promise<RSSRound2Response> {

  // }
}
