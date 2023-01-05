import { generatePrivate } from "@toruslabs/eccrypto";
import { post } from "@toruslabs/http-helpers";
import assert from "assert";
import BN from "bn.js";
import log from "loglevel";
import * as fetch from "node-fetch";

import { dotProduct, ecCurve, generatePolynomial, getLagrangeCoeffs, getShare, hexPoint, recover, RSSClient } from "../src";
(globalThis as any).fetch = fetch;

describe("RSS Client", function () {
  it("#should return correct values", async function () {
    const factorKeys = [new BN(generatePrivate()), new BN(generatePrivate())];
    const factorPubs = factorKeys.map((key) => hexPoint(ecCurve.g.mul(key)));
    const serverEndpoints = [
      "http://localhost:7071",
      "http://localhost:7072",
      "http://localhost:7073",
      "http://localhost:7074",
      "http://localhost:7075",
    ];
    const serverCount = serverEndpoints.length;

    const serverPrivKeys = [];
    for (let i = 0; i < serverCount; i++) {
      serverPrivKeys.push(new BN(generatePrivate()));
    }
    const serverPubKeys = serverPrivKeys.map((privKey) => hexPoint(ecCurve.g.mul(privKey)));
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return post(`${endpoint}/private_key`, { private_key: serverPrivKeys[i] }).catch((e) => log.error(e));
      })
    );
    // const serverPubKeys = await Promise.all(
    //   serverEndpoints.map((endpoint) => {
    //     return get<PointHex>(`${endpoint}/public_key`);
    //   })
    // );
    const serverThreshold = 3;
    const inputIndex = 2;
    const tssPrivKey = new BN(generatePrivate());
    const tssPubKey = ecCurve.g.mul(tssPrivKey);
    const masterPoly = generatePolynomial(1, tssPrivKey);
    const tss2 = getShare(masterPoly, inputIndex);
    const serverPoly = generatePolynomial(serverThreshold - 1, getShare(masterPoly, 1));

    // set tssShares on servers
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return post(`${endpoint}/tss_share`, {
          label: "test",
          tss_share_hex: getShare(serverPoly, i + 1).toString(16, 64),
        }).catch((e) => log.error(e));
      })
    );

    // simulate new key assign
    const dkg2Priv = new BN(generatePrivate());
    const dkg2Pub = ecCurve.g.mul(dkg2Priv);
    const serverPoly2 = generatePolynomial(serverThreshold - 1, dkg2Priv);
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return post(`${endpoint}/tss_share`, {
          label: "test`2",
          tss_share_hex: getShare(serverPoly2, i + 1).toString(16, 64),
        }).catch((e) => log.error(e));
      })
    );

    const rssClient = new RSSClient({
      serverEndpoints,
      serverPubKeys,
      serverThreshold,
      tssPubKey: hexPoint(tssPubKey),
    });
    const targetIndexes = [2, 3];
    const refreshed = await rssClient.refresh({
      dkgNewPub: hexPoint(dkg2Pub),
      inputIndex,
      inputShare: tss2,
      selectedServers: [1, 2, 3],
      factorPubs,
      targetIndexes,
      vid1: "test",
      vid2: "test`2",
      vidSigs: [],
    });

    const recovered = await Promise.all(
      refreshed.map((r, i) =>
        recover({
          factorKey: factorKeys[i],
          serverEncs: r.serverFactorEncs,
          userEnc: r.userFactorEnc,
          selectedServers: [1, 2, 3],
        })
      )
    );

    const tssShares = recovered.map((r) => r.tssShare);

    // check that shares are valid

    targetIndexes.map((target, i) => {
      const interpolationLCs = [1, target].map((a) => getLagrangeCoeffs([1, target], a));

      const shares = [dkg2Priv, tssShares[i]];

      const _tssPrivKey = dotProduct(interpolationLCs, shares).umod(ecCurve.n);

      assert.equal(_tssPrivKey.toString(16, 64), tssPrivKey.toString(16, 64));

      return null;
    });

    return true;
  });
});
