"use client";

import { useParams } from "next/navigation";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportAbsent from "@/components/analysis/ReportAbsent";
import { reportAbsence } from "@/components/analysis/reportAbsence";
import { formatBytes } from "@/lib/report-utils";
import CopyButton from "@/components/ui/CopyButton";
import Field from "@/components/ui/Field";
import Section from "@/components/ui/Section";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import ReputationSection from "@/components/analysis/ReputationSection";
import {
  readIdentitySection,
  signingBadge,
  type HashField,
  type SigningBadge,
} from "@/components/analysis/identitySection";
import EvidenceChips from "@/components/analysis/EvidenceChips";
import {
  binarySectionKeys,
  isCoveredBySection,
  saysSomething,
  sectionsForTab,
} from "@/components/analysis/reportSections";
import { humaniseRow } from "@/lib/humanise";
import { fileTypeLabel, platformLabel } from "@/types/malware-report";
import type { EvidenceSection, SampleIdentity } from "@/types/malware-report";

export default function IdentityTab() {
  const { report, job, loading, reportError } = useReport();
  const params = useParams();
  const jobId = (params.id as string) ?? "";

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  /* No report is not an empty report: say which absence this is rather than
   * drawing this tab's negative (`reportAbsence`). */
  const absent = reportAbsence({ report, job, reportError });
  if (absent) return <ReportAbsent absence={absent} />;

  const identity: SampleIdentity | undefined = report?.malware_report?.identity;
  // What the identifying tools returned, in their own shape: the `identity`
  // key/value block and the header table of whichever binary-info tool ran.
  // These lead the page; the typed block below is the report's own summary of
  // the same facts and stands down when a header section already carries them.
  const reportSections = report?.malware_report?.sections;
  /* The `identity` section is the one that overlaps this tab's own blocks: its
   * hashes are the File hashes block and its three signing rows are one fact
   * about one format. It is split rather than drawn as it arrives. */
  const tabSections = sectionsForTab(reportSections, "identity", report?.section_tabs);
  const identitySection = tabSections.find((section) => section.key === "identity") ?? null;
  const {
    section: splitIdentity,
    hashes: ledgerHashes,
    signing: sectionStatesSigning,
    states: sectionStates,
  } = readIdentitySection(
    identitySection,
    report?.malware_report?.identity?.file_type,
  );
  const evidenceSections = tabSections.flatMap((section) =>
    section.key === "identity"
      ? splitIdentity
        ? [splitIdentity]
        : []
      : [readableHeader(section)],
  );
  const showsTypedIdentity = !isCoveredBySection(reportSections, binarySectionKeys("header"));

  /* The ledger's fingerprints lead and the typed block fills in the rest, so a
   * report with no typed identity still shows what the `hashes` tool answered
   * — the rows above were taken out of the table on the promise that this
   * block draws them. */
  const hashRows = HASH_ROWS.map(({ field, label }) => ({
    field,
    label,
    value: ledgerHashes[field] ?? identity?.hashes?.[field as keyof SampleIdentity["hashes"]] ?? "",
  })).filter((row) => saysSomething(row.value));

  const hashes = hashRows.length > 0 && (
    <Section title="File hashes" count={hashRows.length}>
      <div className="space-y-2">
        {hashRows.map((row) => (
          <HashRow key={row.field} label={row.label} value={row.value} />
        ))}
      </div>
    </Section>
  );
  const packing = <PackingAndBuild report={report} />;

  if (!identity) {
    return (
      <div className="space-y-4">
        <ArtifactSections sections={evidenceSections} />
        {evidenceSections.length === 0 && !hashes && (
          <Section title="Identity and metadata" empty emptyText="No identifying tool answered for this sample" />
        )}
        {packing}
        {hashes}
        <ReputationSection jobId={jobId} report={report?.malware_report} enabled={!loading} />
      </div>
    );
  }

  const sigBadge = signingBadge(identity.signing);
  const sigState = { label: sigBadge.label, cls: SIGNING_TONE[sigBadge.tone] };

  return (
    <div className="space-y-4">
      <ArtifactSections sections={evidenceSections} />

      {showsTypedIdentity && (
      <Section
        title="Identity and metadata"
        actions={
          /* Stands down when the table above already says whether the sample
             is signed; the signing check's own entry follows the badge, so it
             can be traced back to the call that established it. */
          !sectionStatesSigning ? (
            <>
              <span className={`text-[11px] font-medium px-2 py-0.5 rounded border ${sigState.cls}`}>
                {sigState.label}
              </span>
              {identity.signing.evidence_id && <EvidenceChips ids={[identity.signing.evidence_id]} />}
            </>
          ) : undefined
        }
      >
        {/* A row whose value is nothing is not a row. Seven labels above
            seven "(unknown)"s said only that the extractor has seven fields. */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { label: "File name", value: identity.file_name ?? "" },
            { label: "File type", value: identity.file_type ? fileTypeLabel(identity.file_type) : "" },
            {
              label: "Platform",
              value:
                identity.platform && identity.platform !== "unknown"
                  ? platformLabel(identity.platform)
                  : "",
            },
            {
              label: "Size",
              value: identity.file_size_bytes ? formatBytes(identity.file_size_bytes) : "",
            },
            { label: "MIME type", value: identity.mime_type ?? "" },
            {
              label: "Compile timestamp",
              value: identity.compile_timestamp
                ? new Date(identity.compile_timestamp).toLocaleString()
                : "",
            },
            { label: "Language / compiler", value: identity.language_or_compiler ?? "" },
            // What the format tool read out of the header: the machine, and
            // whether the image is a library — a DLL submitted under an .exe
            // name is a fact a reader needs before trying to run it.
            { label: "Architecture", value: identity.architecture ?? "" },
            {
              label: "Image",
              value:
                identity.is_dll === true ? "DLL" : identity.is_dll === false ? "executable" : "",
            },
            { label: "Export directory name", value: identity.export_name ?? "" },
            { label: "Internal name", value: identity.internal_name ?? "" },
          ]
            // A field the ledger table above already carries is not drawn
            // again: `size` appeared in both tables on the one screen.
            .filter((field) => saysSomething(field.value) && !sectionStates.has(field.label))
            .map((field) => (
              <Field key={field.label} label={field.label} value={field.value} />
            ))}
        </div>
      </Section>
      )}

      {packing}

      {/* Every fingerprint the run computed, in the one place that holds them.
        * A hash no tool produced is absent rather than drawn as a dash: ssdeep
        * and tlsh need an optional library and imphash needs an import table,
        * and an empty row reads as a missing value rather than an
        * inapplicable one. */}
      {hashes}

      <ReputationSection jobId={jobId} report={report?.malware_report} enabled={!loading} />

      {identity.signing.is_signed && (
        <Section title="Code signing">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              { label: "Signer subject", value: identity.signing.signer_subject ?? "" },
              { label: "Issuer", value: identity.signing.signer_issuer ?? "" },
              {
                label: "Signature valid",
                value:
                  identity.signing.signature_valid === null
                    ? "unverified"
                    : identity.signing.signature_valid
                      ? "yes"
                      : "no",
              },
            ]
              .filter((field) => saysSomething(field.value))
              .map((field) => (
                <Field key={field.label} label={field.label} value={field.value} />
              ))}
          </div>
        </Section>
      )}
    </div>
  );
}

/**
 * How the file was built and wrapped: the packer the detectors matched (with
 * how sure each was and how it matched), the debug path the build left, and
 * the obfuscation the static pass saw. Part of what the file is, so it sits
 * with its identity.
 */
function PackingAndBuild({ report }: { report: ReturnType<typeof useReport>["report"] }) {
  const staticData = report?.malware_report?.static;
  if (!staticData) return null;
  const packerMatches = staticData.packer_matches ?? [];
  const has =
    Boolean(staticData.packer_hint) ||
    packerMatches.length > 0 ||
    staticData.obfuscation_indicators.length > 0 ||
    Boolean(staticData.pdb_path);
  return (
    <Section title="Packing and build" empty={!has}>
      <div className="space-y-2 text-sm text-text-primary">
        {/* Ranked matches beat the bare hint: a reader needs to know whether
          * the detector saw a section name or just a string. */}
        {packerMatches.length > 0 ? (
          <div className="space-y-1">
            {packerMatches.map((pm, i) => (
              <div key={i}>
                {pm.name}
                {pm.kind && <span className="text-text-muted"> ({pm.kind})</span>}
                <span className="ml-2 font-mono text-xs text-text-muted">
                  {typeof pm.confidence === "number" ? pm.confidence.toFixed(2) : "-"}
                  {pm.method ? ` · ${pm.method}` : ""}
                </span>
              </div>
            ))}
          </div>
        ) : (
          staticData.packer_hint && (
            <div>
              <span className="text-text-muted">Packer hint:</span> {staticData.packer_hint}
            </div>
          )
        )}
        {staticData.pdb_path && (
          <div>
            <span className="text-text-muted">Debug PDB:</span>{" "}
            <span className="break-all font-mono text-xs">{staticData.pdb_path}</span>
          </div>
        )}
        {staticData.obfuscation_indicators.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {staticData.obfuscation_indicators.map((ind, i) => (
              <span key={`${ind}-${i}`} className="rounded bg-status-orange/10 px-1.5 py-0.5 text-[11px] text-status-orange">
                {ind}
              </span>
            ))}
          </div>
        )}
      </div>
    </Section>
  );
}

/**
 * A binary-info tool's header table, read back into the words it means.
 *
 * `machine 34404`, `subsystem 2`, `timestamp 1566949827` and `size 4486656`
 * are what the file format stores; none of them is a fact about the sample
 * until it is named. Scoped to the header tables rather than done in
 * `ArtifactTable`, which is deliberately ignorant of what a tool's fields are.
 */
function readableHeader(section: EvidenceSection): EvidenceSection {
  if (section.kind !== "kv" || !/_header$/.test(section.key)) return section;
  return { ...section, rows: (section.rows ?? []).map(humaniseRow) };
}

/** How each signing answer is coloured; "not checked" is drawn apart from "no". */
const SIGNING_TONE: Record<SigningBadge["tone"], string> = {
  signed: "text-status-green bg-status-green/10 border-status-green/30",
  invalid: "text-status-red bg-status-red/10 border-status-red/30",
  unsigned: "text-text-muted bg-bg-active border-border",
  unchecked: "text-text-muted bg-bg-surface border-dashed border-border",
};

/** The hashes a reader knows by name, in the order they are usually quoted. */
const HASH_ROWS: { field: HashField; label: string }[] = [
  { field: "md5", label: "MD5" },
  { field: "sha1", label: "SHA-1" },
  { field: "sha256", label: "SHA-256" },
  { field: "sha512", label: "SHA-512" },
  { field: "imphash", label: "Imphash" },
  { field: "telfhash", label: "Telfhash" },
  { field: "ssdeep", label: "SSDeep" },
  { field: "tlsh", label: "TLSH" },
];

function HashRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-text-muted w-20 shrink-0">
        {label}
      </span>
      {value ? (
        <>
          <code className="flex-1 font-mono text-xs text-status-blue truncate" title={value}>
            {value}
          </code>
          <CopyButton value={value} what={label} />
        </>
      ) : (
        <span className="text-xs text-text-muted">-</span>
      )}
    </div>
  );
}
