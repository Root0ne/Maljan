import { describe, expect, it } from "vitest";

import type { SignatureInfo } from "@/types/malware-report";
import { signingBadge } from "../identitySection";

function signing(over: Partial<SignatureInfo> = {}): SignatureInfo {
  return {
    is_signed: false,
    signer_subject: null,
    signer_issuer: null,
    signature_valid: null,
    ...over,
  };
}

describe("the signature badge", () => {
  it("says UNSIGNED only where the signing check's entry says so", () => {
    expect(signingBadge(signing({ evidence_id: "ev_0004" }))).toEqual({
      label: "UNSIGNED",
      tone: "unsigned",
    });
  });

  it("says the signature was not checked when no check ran", () => {
    expect(signingBadge(signing())).toEqual({ label: "SIGNATURE NOT CHECKED", tone: "unchecked" });
    expect(signingBadge(null)).toEqual({ label: "SIGNATURE NOT CHECKED", tone: "unchecked" });
  });

  it("draws a signed sample signed, and an invalid chain invalid", () => {
    expect(signingBadge(signing({ is_signed: true })).tone).toBe("signed");
    expect(signingBadge(signing({ is_signed: true, signature_valid: false })).tone).toBe("invalid");
    // An unverified chain is not an invalid one.
    expect(signingBadge(signing({ is_signed: true, signature_valid: null })).tone).toBe("signed");
  });
});
