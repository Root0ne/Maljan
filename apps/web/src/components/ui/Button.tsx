import type { ButtonHTMLAttributes, ReactNode } from "react";

/**
 * The console's one button.
 *
 * Three weights, and the weight is the message: `primary` is the single thing
 * a view asks the reader to do next, so a view holds at most one of them
 * (`data-variant` lets a test count); `secondary` is every other action;
 * `ghost` is a quiet control that sits inside a row or a header. A disabled
 * button says why beside it, never only in a `title` nobody can hover.
 */
export type ButtonVariant = "primary" | "secondary" | "ghost";
export type ButtonSize = "sm" | "md";

/* At least 24 px tall (WCAG 2.5.8) at the small size. Hover is a state, so it
 * arrives with the pointer: no colour transition (styleRules). */
const BASE =
  "inline-flex items-center justify-center gap-1.5 rounded font-medium whitespace-nowrap disabled:cursor-not-allowed";

const VARIANT: Record<ButtonVariant, string> = {
  primary:
    "bg-accent-fill text-white border border-accent-fill hover:bg-accent-fill-hover hover:border-accent-fill-hover disabled:bg-bg-active disabled:border-border disabled:text-text-disabled",
  secondary:
    "bg-bg-surface text-text-primary border border-border hover:border-text-muted hover:bg-bg-hover disabled:text-text-disabled disabled:hover:border-border",
  ghost:
    "bg-transparent text-text-secondary border border-transparent hover:text-text-primary hover:bg-bg-hover disabled:text-text-disabled",
};

const SIZE: Record<ButtonSize, string> = {
  sm: "min-h-6 px-2 py-0.5 text-xs",
  md: "min-h-8 px-3 py-1 text-sm",
};

/** The class list of a button of `variant` and `size`, for a link drawn as one. */
export function buttonClass(variant: ButtonVariant = "secondary", size: ButtonSize = "md"): string {
  return `${BASE} ${VARIANT[variant]} ${SIZE[size]}`;
}

export default function Button({
  variant = "secondary",
  size = "md",
  className = "",
  type = "button",
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  children?: ReactNode;
}) {
  return (
    <button
      type={type}
      data-variant={variant}
      className={`${buttonClass(variant, size)} ${className}`.trim()}
      {...rest}
    >
      {children}
    </button>
  );
}
