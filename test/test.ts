import { generatePrivate } from "@toruslabs/eccrypto";
import axios from "axios";
import BN from "bn.js";

import { ecCurve, generatePolynomial, getShare, hexPoint, RSSClient } from "../src";

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
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return axios.post(`${endpoint}/private_key`, { private_key: serverPrivKeys[i] });
      })
    );
    const serverPubKeys = await Promise.all(
      serverEndpoints.map((endpoint) => {
        return axios.get(`${endpoint}/public_key`).then((a) => a.data);
      })
    );
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
        return axios.post(`${endpoint}/tss_share`, {
          label: "test",
          tss_share_hex: getShare(serverPoly, i + 1).toString(16, 64),
        });
      })
    );

    // simulate new key assign
    const dkg2Priv = new BN(generatePrivate());
    const dkg2Pub = ecCurve.g.mul(dkg2Priv);
    const serverPoly2 = generatePolynomial(serverThreshold - 1, dkg2Priv);
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return axios.post(`${endpoint}/tss_share`, {
          label: "test%2",
          tss_share_hex: getShare(serverPoly2, i + 1).toString(16, 64),
        });
      })
    );

    const rssClient = new RSSClient({
      serverEndpoints,
      serverPubKeys,
      serverThreshold,
      tssPubKey: hexPoint(tssPubKey),
    });
    const refreshResponse = await rssClient.refresh({
      dkgNewPub: hexPoint(dkg2Pub),
      inputIndex,
      inputShare: tss2,
      selectedServers: [1, 2, 3],
      factorPubs,
      targetIndexes: [2],
      vid1: "test",
      vid2: "test%2",
      vidSigs: [],
    });

    const recovered = await Promise.all(
      refreshResponse.map((r, i) =>
        rssClient.recover({
          factorKey: factorKeys[i],
          serverEncs: r.serverFactorEncs,
          userEnc: r.userFactorEnc,
        })
      )
    );

    // eslint-disable-next-line no-console
    console.log(recovered);

    return true;
  });
});
