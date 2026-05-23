# Triage Cloud API - Overview Report

Source: https://tria.ge/docs/cloud-api/overview-report/
Mirrored: 2026-05-23

---

# The Overview Report

This is the Go structure definition of the Overview JSON report that Triage™ generates.

This report can be fetched through the [/samples/{sampleID}/overview.json](../samples/#get-samplessampleidoverviewjson) endpoint.

```go
// Copyright (C) 2019-2022 Hatching B.V.
// All rights reserved.

package triage

type (
    OverviewReport struct {
        Version    string              `json:"version"`
        Sample     OverviewSample      `json:"sample"`
        Tasks      []TaskSummary       `json:"tasks,omitempty"`
        Analysis   OverviewAnalysis    `json:"analysis"`
        Targets    []OverviewTarget    `json:"targets"`
        Errors     []ReportedFailure   `json:"errors,omitempty"`
        Signatures []Signature         `json:"signatures,omitempty"`
        Extracted  []OverviewExtracted `json:"extracted,omitempty"`
    }
    OverviewSample struct {
        TargetDesc
        Created   time.Time     `json:"created"`
        Completed time.Time     `json:"completed"`
        IOCs      *OverviewIOCs `json:"iocs,omitempty"`
    }
    TaskSummary struct {
        Sample   string   `json:"sample"`
        Kind     string   `json:"kind,omitempty"`
        Name     string   `json:"name,omitempty"`
        Status   string   `json:"status,omitempty"`
        TTP      []string `json:"ttp,omitempty"`
        Tags     []string `json:"tags,omitempty"`
        Score    int      `json:"score,omitempty"`
        Target   string   `json:"target,omitempty"`
        Backend  string   `json:"backend,omitempty"`
        Resource string   `json:"resource,omitempty"`
        Platform string   `json:"platform,omitempty"`
        TaskName string   `json:"task_name,omitempty"`
        Failure  string   `json:"failure,omitempty"`
        QueueID  int64    `json:"queue_id,omitempty"`
        Pick     string   `json:"pick,omitempty"`
    }
    OverviewAnalysis struct {
        Score  int      `json:"score"`
        Family []string `json:"family,omitempty"`
        Tags   []string `json:"tags,omitempty"`
    }
    OverviewTarget struct {
        Tasks []string `json:"tasks"`
        TargetDesc
        Tags       []string      `json:"tags,omitempty"`
        Family     []string      `json:"family,omitempty"`
        Signatures []Signature   `json:"signatures"`
        IOCs       *OverviewIOCs `json:"iocs,omitempty"`
    }
    ReportedFailure struct {
        Task    string `json:"task,omitempty"`
        Backend string `json:"backend,omitempty"`
        Reason  string `json:"reason"`
    }
    OverviewExtracted struct {
        Tasks []string `json:"tasks"`
        *Extract
    }
    TargetDesc struct {
        ID              string   `json:"id,omitempty"`
        CompatScore     int      `json:"score,omitempty"`
        Submitted       string   `json:"submitted,omitempty"`
        CompatCompleted string   `json:"completed,omitempty"`
        Target          string   `json:"target,omitempty"`
        Pick            string   `json:"pick,omitempty"`
        Type            string   `json:"type,omitempty"`
        Size            int64    `json:"size,omitempty"`
        MD5             string   `json:"md5,omitempty"`
        SHA1            string   `json:"sha1,omitempty"`
        SHA256          string   `json:"sha256,omitempty"`
        SHA512          string   `json:"sha512,omitempty"`
        Filetype        string   `json:"filetype,omitempty"`
        StaticTags      []string `json:"static_tags,omitempty"`
    }
    Signature struct {
        Label       string      `json:"label,omitempty"`
        Name        string      `json:"name"`
        Score       int         `json:"score,omitempty"`
        TTP         []string    `json:"ttp,omitempty"`
        Tags        []string    `json:"tags,omitempty"`
        Indicators  []Indicator `json:"indicators,omitempty"`
        YaraRule    string      `json:"yara_rule,omitempty"`
        Description string      `json:"desc,omitempty"`
        URL         string      `json:"url,omitempty"`
    }
    Extract struct {
        DumpedFile  string       `json:"dumped_file,omitempty"`
        Resource    string       `json:"resource,omitempty"`
        Config      *Config      `json:"config,omitempty"`
        Path        string       `json:"path,omitempty"`
        RansomNote  *Ransom      `json:"ransom_note,omitempty"`
        Dropper     *Dropper     `json:"dropper,omitempty"`
        Credentials *Credentials `json:"credentials,omitempty"`
    }
    OverviewIOCs struct {
        URLs    []string `json:"urls,omitempty"`
        Domains []string `json:"domains,omitempty"`
        IPs     []string `json:"ips,omitempty"`
    }
    Indicator struct {
        IOC          string `json:"ioc,omitempty"`
        Description  string `json:"description,omitempty"`
        At           uint32 `json:"at,omitempty"`
        SourcePID    uint64 `json:"pid,omitempty"`
        SourceProcID int32  `json:"procid,omitempty"`
        TargetPID    uint64 `json:"pid_target,omitempty"`
        TargetProcID int32  `json:"procid_target,omitempty"`
        Flow         int    `json:"flow,omitempty"`
        Stream       int    `json:"stream,omitempty"`
        DumpFile     string `json:"dump_file,omitempty"`
        Resource     string `json:"resource,omitempty"`
        YaraRule     string `json:"yara_rule,omitempty"`
    }
    Config struct {
        Family       string        `json:"family,omitempty"`
        Tags         []string      `json:"tags,omitempty"`
        Rule         string        `json:"rule,omitempty"`
        C2           []string      `json:"c2,omitempty"`
        Version      string        `json:"version,omitempty"`
        Botnet       string        `json:"botnet,omitempty"`
        Campaign     string        `json:"campaign,omitempty"`
        Mutex        []string      `json:"mutex,omitempty"`
        Decoy        []string      `json:"decoy,omitempty"`
        Wallet       []string      `json:"wallet,omitempty"`
        DNS          []string      `json:"dns,omitempty"`
        Keys         []Key         `json:"keys,omitempty"`
        Webinject    []string      `json:"webinject,omitempty"`
        CommandLines []string      `json:"command_lines,omitempty"`
        ListenAddr   string        `json:"listen_addr,omitempty"`
        ListenPort   int           `json:"listen_port,omitempty"`
        ListenFor    []string      `json:"listen_for,omitempty"`
        Shellcode    [][]byte      `json:"shellcode,omitempty"`
        ExtractedPE  []string      `json:"extracted_pe,omitempty"`
        Credentials  []Credentials `json:"credentials,omitempty"`
        Attributes   interface{}   `json:"attr,omitempty"`
        Raw          string        `json:"raw,omitempty"`
    }
    Ransom struct {
        Family  string   `json:"family,omitempty"`
        Target  string   `json:"target,omitempty"`
        Emails  []string `json:"emails,omitempty"`
        Wallets []string `json:"wallets,omitempty"`
        URLs    []string `json:"urls,omitempty"`
        Contact []string `json:"contact,omitempty"`
        Note    string   `json:"note"`
    }
    Dropper struct {
        Family   string       `json:"family,omitempty"`
        Language string       `json:"language"`
        Source   string       `json:"source,omitempty"`
        Deobf    string       `json:"deobfuscated,omitempty"`
        URLs     []DropperURL `json:"urls"`
    }
    Credentials struct {
        Flow     int    `json:"flow,omitempty"`
        Protocol string `json:"protocol,omitempty"`
        Host     string `json:"host,omitempty"`
        Port     int    `json:"port,omitempty"`
        User     string `json:"username"`
        Pass     string `json:"password"`
        EmailTo  string `json:"email_to,omitempty"`
    }
    Key struct {
        Kind  string      `json:"kind"`
        Key   string      `json:"key"`
        Value interface{} `json:"value"`
    }
    DropperURL struct {
        Type string `json:"type"`
        URL  string `json:"url"`
    }
)
```
