/**
 * The questions a job is submitted with, one per line of the dialog's box.
 * Each line is one question with its runs of white space collapsed; a blank
 * line is none. The API refuses a blank question, so none is ever sent.
 */
export function questionsFromText(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.split(/\s+/).filter(Boolean).join(" "))
    .filter(Boolean);
}
