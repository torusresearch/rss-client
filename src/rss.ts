import { CustomOptions, Data, get, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import log from "loglevel";

import { importClientRound1, importClientRound2 } from "./importProcess";
import { refreshClientRound1, refreshClientRound2 } from "./refreshProcess";
import { decrypt, dotProduct, ecCurveSecp256k1, ecPoint, EncryptedMessage, getLagrangeCoeff, hexPoint, PointHex } from "./utils";

export type KeyType = "secp256k1" | "ed25519";

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
  keyType: KeyType;
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
  keyType: KeyType;
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

  keyType: KeyType;

  constructor(opts: RSSClientOptions) {
    if (opts.keyType !== "secp256k1" && opts.keyType !== "ed25519") throw new Error("Invalid keyType, only secp256k1 or ed25519 is supported");
    this.keyType = opts.keyType;
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

    const _data = await importClientRound1({
      importKey,
      targetIndexes,
      serversInfo,
      tempPubKey: hexPoint(this.tempPubKey),
      keyType: this.keyType,
    });

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

    const { sums, serverEncs, userFactorEncs } = await importClientRound2({
      targetIndexes,
      rssRound1Responses,
      serverThreshold: this.serverThreshold,
      serverEndpoints: this.serverEndpoints,
      factorPubs,
      tempPrivKey: this.tempPrivKey,
      dkgNewPub,
      tssPubKey: hexPoint(this.tssPubKey),
      keyType: this.keyType,
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

    const _data = await refreshClientRound1({
      inputIndex,
      targetIndexes,
      inputShare,
      serversInfo,
      tempPubKey: hexPoint(this.tempPubKey),
      keyType: this.keyType,
    });

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

    const { sums, serverEncs, userFactorEncs } = await refreshClientRound2({
      targetIndexes,
      rssRound1Responses,
      serverThreshold: this.serverThreshold,
      serverEndpoints: this.serverEndpoints,
      factorPubs,
      tempPrivKey: this.tempPrivKey,
      dkgNewPub,
      tssPubKey: hexPoint(this.tssPubKey),
      keyType: this.keyType,
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
  if (opts.keyType !== "secp256k1" && opts.keyType !== "ed25519") throw new Error("Invalid keyType, only secp256k1 or ed25519 is supported");
  const ecCurve = new EC(keyType);
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
