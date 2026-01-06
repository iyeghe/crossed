import { BufferCV, Cl, ClarityType } from "@stacks/transactions";
import { describe, expect, it } from "vitest";

const contractName = "crossed";
const accounts = simnet.getAccounts();
const wallet1 = accounts.get("wallet_1");
const wallet2 = accounts.get("wallet_2");

if (!wallet1 || !wallet2) {
  throw new Error("Simnet wallets are missing");
}

const zeroSignature = Cl.bufferFromHex("00".repeat(65));

const buildTxTuple = (
  signer: string,
  nonce: number,
  callData: ReturnType<typeof Cl.bufferFromAscii>,
  signature: ReturnType<typeof Cl.bufferFromHex>,
) =>
  Cl.tuple({
    signer: Cl.principal(signer),
    nonce: Cl.uint(nonce),
    "call-data": callData,
    signature,
  });

describe("crossed relay contract", () => {
  it("initializes nonce once and enforces sender", () => {
    const init = simnet.callPublicFn(
      contractName,
      "initialize-nonce",
      [Cl.principal(wallet1)],
      wallet1,
    );
    expect(init.result).toBeOk(Cl.bool(true));

    const repeat = simnet.callPublicFn(
      contractName,
      "initialize-nonce",
      [Cl.principal(wallet1)],
      wallet1,
    );
    expect(repeat.result).toBeErr(Cl.uint(1)); // ERR-ALREADY-INITIALIZED

    const unauthorized = simnet.callPublicFn(
      contractName,
      "initialize-nonce",
      [Cl.principal(wallet1)],
      wallet2,
    );
    expect(unauthorized.result).toBeErr(Cl.uint(6)); // ERR-UNAUTHORIZED
  });

  it("rejects an invalid signature and leaves nonce unchanged", () => {
    const callData = Cl.bufferFromAscii("relay-call");
    const relayed = simnet.callPublicFn(
      contractName,
      "relay-call",
      [Cl.principal(wallet1), Cl.uint(0), callData, zeroSignature],
      wallet1,
    );
    expect(relayed.result).toBeErr(Cl.uint(4)); // ERR-INVALID-SIGNATURE

    const nonce = simnet.callReadOnlyFn(
      contractName,
      "get-nonce",
      [Cl.principal(wallet1)],
      wallet1,
    );
    expect(nonce.result).toBeUint(0);
  });

  it("rejects a call with the wrong nonce early", () => {
    const callData = Cl.bufferFromAscii("wrong-nonce");
    const relayed = simnet.callPublicFn(
      contractName,
      "relay-call",
      [Cl.principal(wallet1), Cl.uint(1), callData, zeroSignature],
      wallet1,
    );
    expect(relayed.result).toBeErr(Cl.uint(2)); // ERR-INVALID-NONCE
  });

  it("relays via the simple hash path and bumps nonce", () => {
    const callData = Cl.bufferFromAscii("simple-path");
    const hash = simnet.callReadOnlyFn(
      contractName,
      "get-message-hash",
      [Cl.principal(wallet2), Cl.uint(0), callData],
      wallet2,
    );
    if (hash.result.type !== ClarityType.Buffer) {
      throw new Error("expected buffer hash from get-message-hash");
    }
    const hashHex = (hash.result as BufferCV).value;

    const relayed = simnet.callPublicFn(
      contractName,
      "relay-call-simple",
      [Cl.principal(wallet2), Cl.uint(0), callData, Cl.bufferFromHex(hashHex)],
      wallet2,
    );
    expect(relayed.result).toBeOk(Cl.bool(true));

    const nonce = simnet.callReadOnlyFn(
      contractName,
      "get-nonce",
      [Cl.principal(wallet2)],
      wallet2,
    );
    expect(nonce.result).toBeUint(1);
  });

  it("processes a non-strict batch and records all failures", () => {
    const tx1 = buildTxTuple(wallet1, 0, Cl.bufferFromAscii("batch-one"), zeroSignature);
    const tx2 = buildTxTuple(wallet2, 0, Cl.bufferFromAscii("batch-two"), zeroSignature);

    const batch = simnet.callPublicFn(
      contractName,
      "relay-batch-calls",
      [Cl.list([tx1, tx2])],
      wallet1,
    );
    expect(batch.result).toBeOk(
      Cl.tuple({ "batch-id": Cl.uint(1), successful: Cl.uint(0), total: Cl.uint(2) }),
    );

    const results = simnet.callReadOnlyFn(
      contractName,
      "get-batch-results",
      [Cl.uint(1)],
      wallet1,
    );
    expect(results.result).toBeSome(Cl.list([Cl.bool(false), Cl.bool(false)]));

    const successRate = simnet.callReadOnlyFn(
      contractName,
      "get-batch-success-rate",
      [Cl.uint(1)],
      wallet1,
    );
    expect(successRate.result).toBeSome(
      Cl.tuple({ successful: Cl.uint(0), total: Cl.uint(2), rate: Cl.uint(0) }),
    );
  });

  it("reverts a strict batch when any transaction fails", () => {
    const tx1 = buildTxTuple(wallet1, 0, Cl.bufferFromAscii("strict-one"), zeroSignature);
    const tx2 = buildTxTuple(wallet2, 0, Cl.bufferFromAscii("strict-two"), zeroSignature);

    const batch = simnet.callPublicFn(
      contractName,
      "relay-batch-calls-strict",
      [Cl.list([tx1, tx2])],
      wallet1,
    );
    expect(batch.result).toBeErr(Cl.uint(10)); // ERR-PARTIAL-BATCH-FAILURE
  });
});
