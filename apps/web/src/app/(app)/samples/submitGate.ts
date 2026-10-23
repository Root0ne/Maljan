/**
 * Whether "Start analysis" may be pressed. Starting while the attached report
 * is still uploading would submit without it, and the run it starts (a sandbox
 * detonation among them) cannot be taken back.
 */
export function canStartAnalysis(state: { submitting: boolean; reportUploading: boolean }): boolean {
  return !state.submitting && !state.reportUploading;
}
