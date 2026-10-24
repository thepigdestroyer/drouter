"use client";

import React from "react";
import Link from "next/link";

export type InkButtonVariant = "primary" | "ghost" | "accent";

export type InkButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: InkButtonVariant;
  href?: string;
};

function updateInkOrigin(e: React.PointerEvent<HTMLElement>) {
  const el = e.currentTarget;
  const rect = el.getBoundingClientRect();
  if (rect.width > 0 && rect.height > 0) {
    const x = Math.round(((e.clientX - rect.left) / rect.width) * 100);
    const y = Math.round(((e.clientY - rect.top) / rect.height) * 100);
    el.style.setProperty("--ink-x", `${x}%`);
    el.style.setProperty("--ink-y", `${y}%`);
  }
}

export function InkButton(props: InkButtonProps): React.JSX.Element {
  const {
    variant = "primary",
    href,
    className = "",
    children,
    type = "button",
    disabled,
    onPointerEnter,
    onPointerMove,
    onPointerDown,
    ...rest
  } = props;

  const baseClass =
    variant === "ghost"
      ? "ep-btn-ghost ep-ink-button ep-ink-button-ghost"
      : variant === "accent"
        ? "ep-btn-accent ep-ink-button ep-ink-button-accent"
        : "ep-btn ep-ink-button ep-ink-button-primary";

  const combinedClassName = `${baseClass} ${className}`.trim();

  const handlePointerEnter = (e: React.PointerEvent<HTMLButtonElement>) => {
    updateInkOrigin(e);
    onPointerEnter?.(e);
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLButtonElement>) => {
    updateInkOrigin(e);
    onPointerMove?.(e);
  };

  const handlePointerDown = (e: React.PointerEvent<HTMLButtonElement>) => {
    updateInkOrigin(e);
    onPointerDown?.(e);
  };

  if (href && !disabled) {
    const {
      form: _form,
      formAction: _formAction,
      formEncType: _formEncType,
      formMethod: _formMethod,
      formNoValidate: _formNoValidate,
      formTarget: _formTarget,
      name: _name,
      value: _value,
      onClick,
      ...anchorCompatProps
    } = rest;

    return (
      <Link
        href={href}
        {...(anchorCompatProps as unknown as Omit<
          React.AnchorHTMLAttributes<HTMLAnchorElement>,
          "href" | "className" | "children" | "onClick"
        >)}
        onClick={
          onClick as unknown as React.MouseEventHandler<HTMLAnchorElement>
        }
        onPointerEnter={updateInkOrigin}
        onPointerMove={updateInkOrigin}
        onPointerDown={updateInkOrigin}
        className={combinedClassName}
      >
        <span className="ep-ink-button-label">{children}</span>
      </Link>
    );
  }

  return (
    <button
      type={type}
      disabled={disabled}
      onPointerEnter={handlePointerEnter}
      onPointerMove={handlePointerMove}
      onPointerDown={handlePointerDown}
      className={combinedClassName}
      {...rest}
    >
      <span className="ep-ink-button-label">{children}</span>
    </button>
  );
}

export default InkButton;
