# Triage Cloud API - Static Report

Source: https://tria.ge/docs/cloud-api/static-report/
Mirrored: 2026-05-23

---

# The Static Report

This is the Go structure definition of the Static JSON report that Triage™ creates.

```go
// Copyright (C) 2019-2022 Hatching B.V.
// All rights reserved.

package triage

type (
    StaticReport struct {
        Version string `json:"version"`

        Sample   ReportSample   `json:"sample"`
        Task     ReportTask     `json:"task"`
        Analysis ReportAnalysis `json:"analysis"`

        Signatures  []*Signature  `json:"signatures,omitempty"`
        Files       []*FileReport `json:"files"`
        UnpackCount int           `json:"unpack_count"`
        ErrorCount  int           `json:"error_count"`
        CompatKind  string        `json:"kind,omitempty"`

        Errors    []ReportedFailure `json:"errors,omitempty"`
        Extracted []*Extract        `json:"extracted,omitempty"`
    }
    ReportSample struct {
        ID        string `json:"sample"`
        Kind      string `json:"kind,omitempty"`
        Size      uint64 `json:"size,omitempty"`
        Target    string `json:"target,omitempty"`
        Submitted string `json:"submitted,omitempty"`
    }
    ReportTask struct {
        ID     string `json:"task"`
        Target string `json:"target,omitempty"`
    }
    ReportAnalysis struct {
        Reported string   `json:"reported,omitempty"`
        Score    int      `json:"score,omitempty"`
        Tags     []string `json:"tags,omitempty"`
    }
    FileReport struct {
        Name    string `json:"filename"`
        RelPath string `json:"relpath,omitempty"`
        Size    uint64 `json:"filesize"`
        Hashes
        Extensions []string `json:"exts"`
        Tags       []string `json:"tags"`
        Filetype   string   `json:"filetype,omitempty"`
        Mime       string   `json:"mime,omitempty"`
        Depth      int      `json:"depth"`
        Error      string   `json:"error,omitempty"`
        Kind       string   `json:"kind"`
        Selected   bool     `json:"selected"`
        RunAs      string   `json:"runas,omitempty"`
        Password   string   `json:"password,omitempty"`
    }
    Hashes struct {
        MD5    string `json:"md5,omitempty"`
        SHA1   string `json:"sha1,omitempty"`
        SHA256 string `json:"sha256,omitempty"`
        SHA512 string `json:"sha512,omitempty"`
    }
)
```
