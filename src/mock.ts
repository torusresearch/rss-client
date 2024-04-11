/* eslint-disable camelcase */
import BN from "bn.js";
import { ec as EC } from "elliptic";

import { ServersInfo } from "./rss";
import {
  decrypt,
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

const { CURVE } = process.env;
const ecCurve = new EC(CURVE || "secp256k1");
const genRandomScalar = () => ecCurve.genKeyPair().getPrivate();

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

export async function RSSRound1Handler(body: RSSRound1Request, getTSSShare: (label: string) => Promise<BN>): Promise<RSSRound1Response> {
  const b = body;
  const auth = b.auth as AuthData;
  // TODO: verify vid (unique label verifierName + verifierID) against vid_sigs (signature from servers on vid)

  if (b.round_name !== "rss_round_1") throw new Error("incorrect round name");
  if (b.server_set !== "old" && b.server_set !== "new") throw new Error("server set must be either 'old' or 'new'");
  // only allow target indexes of 2, 3 for the refresh
  if (!Array.isArray(b.target_index) || b.target_index.filter((elem) => elem !== 2 && elem !== 3).length > 0) {
    throw new Error("invalid target index, only 2, 3 allowed");
  }
  if (b.server_set === "old" && b.old_user_share_index !== 2 && b.old_user_share_index !== 3) {
    throw new Error("invalid index for user share");
  }

  let servers_info: ServersInfo;
  if (b.server_set === "old") {
    servers_info = b.old_servers_info;
  } else {
    servers_info = b.new_servers_info;
  }

  // TODO: check old and new server pubkeys independently, against the registered node list
  // TODO: check server_index independently, against the registered node list

  if (b.server_index <= 0 || b.server_index > servers_info.pubkeys.length) throw new Error("server index out of bounds");
  if (servers_info.selected.filter((selectedIndex) => selectedIndex <= 0 || selectedIndex > servers_info.pubkeys.length).length > 0)
    throw new Error("selected indexes out of bounds");
  if (servers_info.selected.indexOf(b.server_index) === -1) throw new Error("unselected server, should not have received rss round 1 message");

  // calculate appropriate lagrange coefficients
  let finalLagrangeCoeffs;
  if (b.server_set === "old") {
    // firstly, calculate lagrange coefficient for own server sharing poly
    let L = getLagrangeCoeff(servers_info.selected, b.server_index, 0, ecCurve.n);
    // secondly, calculate lagrange coefficient for master sharing poly
    L = L.mul(getLagrangeCoeff([1, b.old_user_share_index], 1, 0, ecCurve.n)).umod(ecCurve.n);
    // thirdly, calculate lagrange coefficient for new master sharing poly
    finalLagrangeCoeffs = b.target_index.map((target) => L.mul(getLagrangeCoeff([0, 1], 0, target, ecCurve.n)).umod(ecCurve.n));
  } else {
    // firstly, calculate lagrange coefficient for own server sharing poly
    const L = getLagrangeCoeff(servers_info.selected, b.server_index, 0, ecCurve.n);
    // secondly, calculate lagrange coefficient for master sharing poly
    finalLagrangeCoeffs = b.target_index.map((target) => L.mul(getLagrangeCoeff([0, 1], 1, target, ecCurve.n)).umod(ecCurve.n));
  }

  // retrieve server tss subshare from db
  const tssServerShare = await getTSSShare(auth.label);

  const masterPolys = [];
  const masterPolyCommits = [];
  const serverPolys = [];
  const serverPolyCommits = [];

  for (let i = 0; i < finalLagrangeCoeffs.length; i++) {
    const lc = finalLagrangeCoeffs[i];
    const m = generatePolynomial(1, lc.mul(tssServerShare).umod(ecCurve.n), genRandomScalar);
    masterPolys.push(m);
    masterPolyCommits.push(
      m.map((coeff) => {
        const gCoeff = ecCurve.g.mul(coeff);
        return hexPoint(gCoeff);
      })
    );
    const s = generatePolynomial(b.new_servers_info.threshold - 1, getShare(m, 1, ecCurve.n), genRandomScalar);
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
        Buffer.from(getShare(masterPoly, 99, ecCurve.n).toString(16, 64), "hex")
      )
    );

    const serverPoly = serverPolys[i];
    const serverEnc = serverEncs[i];
    for (let j = 0; j < b.new_servers_info.pubkeys.length; j++) {
      const pub = b.new_servers_info.pubkeys[j];
      serverEnc.push(
        await encrypt(
          Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"),
          Buffer.from(getShare(serverPoly, j + 1, ecCurve.n).toString(16, 64), "hex")
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

export async function RSSRound2Handler(body: RSSRound2Request, getPrivKey: () => Promise<BN>): Promise<RSSRound2Response> {
  const b = body;
  const privKey = await getPrivKey();
  const privKeyHex = privKey.toString(16, 64);
  const privKeyBuf = Buffer.from(privKeyHex, "hex");
  const data: RSSRound2ResponseData[] = [];
  if (b.round_name !== "rss_round_2") throw new Error("incorrect round name");
  for (let i = 0; i < b.data.length; i++) {
    const factorPubs: PointHex[] = b.data[i].factor_pubkeys;
    // TODO: check that the same factorPub is not used for multiple shares

    const masterCommits = b.data[i].master_commits.map((p) => ecPoint(ecCurve, p));
    const serverCommits = b.data[i].server_commits.map((p) => ecPoint(ecCurve, p));

    const gB0 = masterCommits[0].add(masterCommits[1]);
    const _gB0 = serverCommits[0];
    if (!gB0.eq(_gB0)) {
      throw new Error("server sharing poly commits are inconsistent with master sharing poly commits");
    }

    const encs = b.data[i].server_encs;
    const decs = await Promise.all(
      encs.map((enc) => {
        return decrypt(privKeyBuf, enc);
      })
    );
    const dec = decs.reduce((acc, dBuf) => {
      const dBN = new BN(dBuf);
      return acc.add(dBN).umod(ecCurve.n);
    }, new BN(0));

    const gDec = ecCurve.g.mul(dec);
    let _gDec = serverCommits[0];
    for (let j = 1; j < serverCommits.length; j++) {
      const gBX = serverCommits[j];
      const ind = new BN(b.server_index);
      _gDec = _gDec.add(gBX.mul(ind.pow(new BN(j))));
    }
    if (!gDec.eq(_gDec)) {
      throw new Error("shares are inconsistent with the server poly commits");
    }
    const factorEncs = await Promise.all(
      factorPubs.map((pub) => {
        return encrypt(Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"), Buffer.from(dec.toString(16, 64), "hex"));
      })
    );
    data.push({ encs: factorEncs });
  }

  const resp: RSSRound2Response = {
    data,
    target_index: b.target_index,
  };

  return resp;
}

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

  constructor() {
    this.shareDB = {};
    this.store = {};
    this.tssNonce = {};
  }

  async getTSSShare(label: string): Promise<BN> {
    return this.shareDB[label];
  }

  async getPrivKey(): Promise<BN> {
    return new BN(this.store.privKey.padStart(64, "0"), "hex");
  }

  async get(path: string): Promise<PointHex | Record<string, unknown>> {
    if (path === "/test") {
      return {};
    }
    if (path === "/public_key") {
      return this.pubKey;
    }
    throw new Error(`unknown get path ${path}`);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async post(path: string, data: any): Promise<RSSRound1Response | RSSRound2Response | Record<string, unknown>> {
    const { label, tss_share_hex: tssShareHex } = data;
    if (path === "/tss_share") {
      this.shareDB[label] = new BN(tssShareHex.padStart(64, "0"), "hex");
      return {};
    }
    if (path === "/private_key") {
      const privKey = data.private_key;
      this.store.privKey = privKey;
      this.pubKey = hexPoint(ecCurveSecp256k1.g.mul(privKey));
      return {};
    }
    if (path === "/get_tss_nonce") {
      const { vid, tssTag } = data;
      return { tss_nonce: this.tssNonce[`${vid}\u0015${tssTag}`] };
    }
    if (path === "/set_tss_nonce") {
      const { vid, tssTag, tssNonce } = data;
      this.tssNonce[`${vid}\u0015${tssTag}`] = tssNonce;
      return {};
    }
    if (path === "/rss_round_1") {
      return RSSRound1Handler(data as RSSRound1Request, this.getTSSShare.bind(this));
    }
    if (path === "/rss_round_2") {
      return RSSRound2Handler(data as RSSRound2Request, this.getPrivKey.bind(this));
    }
    throw new Error(`unknown post path ${path}`);
  }

  async RSSRound1Handler(body: RSSRound1Request, getTSSShare: (label: string) => Promise<BN>): Promise<RSSRound1Response> {
    const b = body;
    const auth = b.auth as AuthData;
    // TODO: verify vid (unique label verifierName + verifierID) against vid_sigs (signature from servers on vid)

    if (b.round_name !== "rss_round_1") throw new Error("incorrect round name");
    if (b.server_set !== "old" && b.server_set !== "new") throw new Error("server set must be either 'old' or 'new'");
    // only allow target indexes of 2, 3 for the refresh
    if (!Array.isArray(b.target_index) || b.target_index.filter((elem) => elem !== 2 && elem !== 3).length > 0) {
      throw new Error("invalid target index, only 2, 3 allowed");
    }
    if (b.server_set === "old" && b.old_user_share_index !== 2 && b.old_user_share_index !== 3) {
      throw new Error("invalid index for user share");
    }

    let servers_info: ServersInfo;
    if (b.server_set === "old") {
      servers_info = b.old_servers_info;
    } else {
      servers_info = b.new_servers_info;
    }

    // TODO: check old and new server pubkeys independently, against the registered node list
    // TODO: check server_index independently, against the registered node list

    if (b.server_index <= 0 || b.server_index > servers_info.pubkeys.length) throw new Error("server index out of bounds");
    if (servers_info.selected.filter((selectedIndex) => selectedIndex <= 0 || b.server_index > servers_info.pubkeys.length).length > 0)
      throw new Error("selected indexes out of bounds");
    if (servers_info.selected.indexOf(b.server_index) === -1) throw new Error("unselected server, should not have received rss round 1 message");

    // calculate appropriate lagrange coefficients
    let finalLagrangeCoeffs;
    if (b.server_set === "old") {
      // firstly, calculate lagrange coefficient for own server sharing poly
      let L = getLagrangeCoeff(servers_info.selected, b.server_index, 0, ecCurve.n);
      // secondly, calculate lagrange coefficient for master sharing poly
      L = L.mul(getLagrangeCoeff([1, b.old_user_share_index], 1, 0, ecCurve.n)).umod(ecCurve.n);
      // thirdly, calculate lagrange coefficient for new master sharing poly
      finalLagrangeCoeffs = b.target_index.map((target) => L.mul(getLagrangeCoeff([0, 1], 0, target, ecCurve.n)).umod(ecCurve.n));
    } else {
      // firstly, calculate lagrange coefficient for own server sharing poly
      const L = getLagrangeCoeff(servers_info.selected, b.server_index, 0, ecCurve.n);
      // secondly, calculate lagrange coefficient for master sharing poly
      finalLagrangeCoeffs = b.target_index.map((target) => L.mul(getLagrangeCoeff([0, 1], 1, target, ecCurve.n)).umod(ecCurve.n));
    }

    // retrieve server tss subshare from db
    const tssServerShare = await getTSSShare(auth.label);

    const masterPolys = [];
    const masterPolyCommits = [];
    const serverPolys = [];
    const serverPolyCommits = [];

    for (let i = 0; i < finalLagrangeCoeffs.length; i++) {
      const lc = finalLagrangeCoeffs[i];
      const m = generatePolynomial(1, lc.mul(tssServerShare).umod(ecCurve.n), genRandomScalar);
      masterPolys.push(m);
      masterPolyCommits.push(
        m.map((coeff) => {
          const gCoeff = ecCurve.g.mul(coeff);
          return hexPoint(gCoeff);
        })
      );
      const s = generatePolynomial(b.new_servers_info.threshold - 1, getShare(m, 1, ecCurve.n), genRandomScalar);
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
          Buffer.from(getShare(masterPoly, 99, ecCurve.n).toString(16, 64), "hex") // Note: this is because 99 is the hardcoded value when doing rss DKG hierarchical sharing
        )
      );

      const serverPoly = serverPolys[i];
      const serverEnc = serverEncs[i];
      for (let j = 0; j < b.new_servers_info.pubkeys.length; j++) {
        const pub = b.new_servers_info.pubkeys[j];
        serverEnc.push(
          await encrypt(
            Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"),
            Buffer.from(getShare(serverPoly, j + 1, ecCurve.n).toString(16, 64), "hex")
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

  async RSSRound2Handler(body: RSSRound2Request, getPrivKey: () => Promise<BN>): Promise<RSSRound2Response> {
    const b = body;
    const privKey = await getPrivKey();
    const privKeyHex = privKey.toString(16, 64);
    const privKeyBuf = Buffer.from(privKeyHex, "hex");
    const data: RSSRound2ResponseData[] = [];
    if (b.round_name !== "rss_round_2") throw new Error("incorrect round name");
    for (let i = 0; i < b.data.length; i++) {
      const factorPubs: PointHex[] = b.data[i].factor_pubkeys;
      // TODO: check that the same factorPub is not used for multiple shares

      const masterCommits = b.data[i].master_commits.map((p) => ecPoint(ecCurve, p));
      const serverCommits = b.data[i].server_commits.map((p) => ecPoint(ecCurve, p));

      const gB0 = masterCommits[0].add(masterCommits[1]);
      const _gB0 = serverCommits[0];
      if (!gB0.eq(_gB0)) {
        throw new Error("server sharing poly commits are inconsistent with master sharing poly commits");
      }

      const encs = b.data[i].server_encs;
      const decs = await Promise.all(
        encs.map((enc) => {
          return decrypt(privKeyBuf, enc);
        })
      );
      const dec = decs.reduce((acc, dBuf) => {
        const dBN = new BN(dBuf);
        return acc.add(dBN).umod(ecCurve.n);
      }, new BN(0));

      const gDec = ecCurve.g.mul(dec);
      let _gDec = serverCommits[0];
      for (let j = 1; j < serverCommits.length; j++) {
        const gBX = serverCommits[j];
        const ind = new BN(b.server_index);
        _gDec = _gDec.add(gBX.mul(ind.pow(new BN(j))));
      }
      if (!gDec.eq(_gDec)) {
        throw new Error("shares are inconsistent with the server poly commits");
      }
      const factorEncs = await Promise.all(
        factorPubs.map((pub) => {
          return encrypt(Buffer.from(`04${pub.x.padStart(64, "0")}${pub.y.padStart(64, "0")}`, "hex"), Buffer.from(dec.toString(16, 64), "hex"));
        })
      );
      data.push({ encs: factorEncs });
    }

    const resp: RSSRound2Response = {
      data,
      target_index: b.target_index,
    };

    return resp;
  }
}
