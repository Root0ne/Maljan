/**
 * What a failed probe says, in words rather than in exception classes.
 *
 * "failed · 40 ms · model list: ConnectError: All connection attempts failed"
 * is the transport's own vocabulary shown to somebody who is trying to
 * configure a model server. The class is kept — it is what a bug report needs
 * — and a sentence saying what it means is put in front of it.
 *
 * Only the transport classes are translated. Anything the API said in its own
 * words is already a sentence and is passed through untouched: this must not
 * become a place where a backend message is rewritten into a worse one.
 */

/** Exception classes a probe can fail with, and what each one means. */
const MEANS: { matches: RegExp; sentence: string }[] = [
  {
    matches: /\bConnectError\b|\bConnectionRefused/,
    sentence: "nothing answered at that address — check the host and the port, and that the server is running",
  },
  {
    matches: /\bConnectTimeout\b|\bReadTimeout\b|\bTimeoutError\b/,
    sentence: "the endpoint accepted the connection but did not answer in time",
  },
  {
    matches: /\bSSLError\b|\bCertificateError\b|CERTIFICATE_VERIFY/,
    sentence: "the endpoint's TLS certificate was refused",
  },
  {
    matches: /\b(401|403|Unauthorized|Forbidden)\b/,
    sentence: "the endpoint answered, and refused the credentials",
  },
  {
    matches: /\bNameResolutionError\b|getaddrinfo|\bDNS\b/,
    sentence: "the host name did not resolve",
  },
];

/** The probe's own detail, with a sentence in front of it where one is known. */
export function probeDetail(detail: string): string {
  const text = (detail ?? "").trim();
  if (!text) return text;
  const known = MEANS.find((entry) => entry.matches.test(text));
  return known ? `${known.sentence} (${text})` : text;
}
