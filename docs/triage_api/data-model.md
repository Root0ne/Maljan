# Triage - Data Model

Source: https://tria.ge/docs/data-model/
Mirrored: 2026-05-23

---

# The Data Model

## Sample

A Sample represents the combined state of the analysis process of a sample that has been submitted. A sample can be either a file, an archive containing multiple files, or an URL.

## Analysis Profile

An *Analysis Profile* is a set of parameters that control the execution of a *Task*.

## Static Report

Samples undergo *static analysis* before being ran in a sandbox. This part of the process creates the *Static Report*, a file containing information about the sample based on analysing the sample file without running it. This report is used to select an appropriate *Analysis Profile* to run the sample in one or more sandbox environments.

## Analysis Task

Also referred to as just a *Task*. Samples have one or more *Tasks*, one for each sandbox run initiated.

## Task Report

The Task Report is generated from the raw information gathered from a task that has been executed. It contains information like which processes have been spawned, [TTPs](https://attack.mitre.org/) (Tactics, Techniques, and Procedures) and network connections.

# The Analysis Process

## Submission

A sample is submitted by a user through the web-interface or API.

Samples can be submitted *interactively* which allows more manual interaction with the analysis process, such as selecting an *Analysis Profile* when static analysis is finished.

## Static Analysis

The sample is scheduled for static analysis. When finished, the *Static Report* is generated.

If the sample was submitted *interactively*, an *Analysis Profile* must be manually selected before the analysis process will continue.

## Task Execution

When all tasks have been configured, the tasks are scheduled to run on the sandbox. Tasks are scheduled based on availability of resources, so multiple tasks may run in parallel. When a task has been completed a report is generated.
