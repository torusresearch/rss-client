import assert from "assert";
import log from "loglevel";

import { dotProduct, ecCurve, ecCurveSecp256k1, generatePolynomial, getLagrangeCoeffs, getShare, hexPoint, postEndpoint, recover, RSSClient, setCurve } from "../src";
import { MockServer } from "../src/mock";
(globalThis as any).fetch = fetch;

if (process.env.CURVE) {
  setCurve(process.env.CURVE);
}

describe("RSS Client", function () {
  // it("#should mock servers", async function() {
  //   const factorKeys = [new BN(generatePrivate()), new BN(generatePrivate())];
  //   const factorPubs = factorKeys.map((key) => hexPoint(ecCurveSecp256k1.g.mul(key)));
  //   const serverEndpoints = [
  //     "http://localhost:7071",
  //     "http://localhost:7072",
  //     "http://localhost:7073",
  //     "http://localhost:7074",
  //     "http://localhost:7075",
  //   ];
  // });
  it("#should return correct values for import", async function () {
    const testId = "test@test.com\u001cgoogle";

    const factorKeyPairs = [ecCurveSecp256k1.genKeyPair(), ecCurveSecp256k1.genKeyPair()];
    const factorKeys = factorKeyPairs.map(kp => kp.getPrivate());
    const factorPubs = factorKeyPairs.map((kp) => hexPoint(kp.getPublic()));
    
    const serverEndpoints = [new MockServer(), new MockServer(), new MockServer(), new MockServer(), new MockServer()];
    const serverKeyPairs = serverEndpoints.map(_ => ecCurveSecp256k1.genKeyPair());
    const serverPrivKeys = serverKeyPairs.map(kp => kp.getPrivate());
    const serverPubKeys = serverKeyPairs.map((kp) => hexPoint(kp.getPublic()));

    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return postEndpoint(endpoint, "/private_key", { private_key: serverPrivKeys[i].toString(16, 64) }).catch((e) => log.error(e));
      })
    );
    
    const serverThreshold = 3;
    const importKeyPair = ecCurve.genKeyPair(); 
    const importKey = importKeyPair.getPrivate();
    const tssPubKey = importKeyPair.getPublic();

    // simulate new key assign
    const dkg2KeyPair = ecCurve.genKeyPair();
    const dkg2Priv = dkg2KeyPair.getPrivate();
    const dkg2Pub = dkg2KeyPair.getPublic();
    const serverPoly2 = generatePolynomial(serverThreshold - 1, dkg2Priv);
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        const shareHex = getShare(serverPoly2, i + 1).toString(16, 64);

        return postEndpoint(endpoint, "/tss_share", {
          label: `${testId}\u0015default\u00161`,
          tss_share_hex: shareHex,
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
    const refreshed = await rssClient.import({
      importKey,
      dkgNewPub: hexPoint(dkg2Pub),
      selectedServers: [1, 2, 3],
      factorPubs,
      targetIndexes,
      newLabel: `${testId}\u0015default\u00161`,
      sigs: [],
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

      assert.equal(_tssPrivKey.toString(16, 64), importKey.toString(16, 64));

      return null;
    });

    return true;
  });

  it("#should return correct values for refresh", async function () {
    const testId = "test@test.com\u001cgoogle";

    const factorKeyPairs = [ecCurveSecp256k1.genKeyPair(), ecCurveSecp256k1.genKeyPair()];
    const factorKeys = factorKeyPairs.map(kp => kp.getPrivate());
    const factorPubs = factorKeyPairs.map((kp) => hexPoint(kp.getPublic()));
    
    const serverEndpoints = [new MockServer(), new MockServer(), new MockServer(), new MockServer(), new MockServer()];
    const serverKeyPairs = serverEndpoints.map(_ => ecCurveSecp256k1.genKeyPair());
    const serverPrivKeys = serverKeyPairs.map(kp => kp.getPrivate());
    const serverPubKeys = serverKeyPairs.map((kp) => hexPoint(kp.getPublic()));

    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return postEndpoint(endpoint, "/private_key", { private_key: serverPrivKeys[i].toString(16, 64) }).catch((e) => log.error(e));
      })
    );

    const serverThreshold = 3;
    const inputIndex = 2;

    const tssKeyPair = ecCurve.genKeyPair();
    const tssPrivKey = tssKeyPair.getPrivate();
    const tssPubKey = tssKeyPair.getPublic();
    
    const masterPoly = generatePolynomial(1, tssPrivKey);
    const tss2 = getShare(masterPoly, inputIndex);
    const serverPoly = generatePolynomial(serverThreshold - 1, getShare(masterPoly, 1));

    // set tssShares on servers
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        return postEndpoint(endpoint, "/tss_share", {
          label: `${testId}\u0015default\u00160`,
          tss_share_hex: getShare(serverPoly, i + 1).toString(16, 64),
        }).catch((e) => log.error(e));
      })
    );

    // simulate new key assign
    const dkg2KeyPair = ecCurve.genKeyPair();
    const dkg2Priv = dkg2KeyPair.getPrivate();
    const dkg2Pub = dkg2KeyPair.getPublic();
    const serverPoly2 = generatePolynomial(serverThreshold - 1, dkg2Priv);
    await Promise.all(
      serverEndpoints.map((endpoint, i) => {
        const shareHex = getShare(serverPoly2, i + 1).toString(16, 64);

        return postEndpoint(endpoint, "/tss_share", {
          label: `${testId}\u0015default\u00161`,
          tss_share_hex: shareHex,
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
      oldLabel: `${testId}\u0015default\u00160`,
      newLabel: `${testId}\u0015default\u00161`,
      sigs: [],
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
