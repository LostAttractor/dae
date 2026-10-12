import { Button as AstryxButton, type ButtonProps } from "@astryxdesign/core/Button";
import { Badge as AstryxBadge, type BadgeProps } from "@astryxdesign/core/Badge";
import { TextInput as AstryxTextInput, type TextInputProps } from "@astryxdesign/core/TextInput";
import { Tab as AstryxTab, type TabProps } from "@astryxdesign/core/TabList";
import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes } from "react";

// Astryx forwards these native attributes but omits them from its public props.
// Keep the integration explicit and limited to the attributes used by this UI.
export function Button(props: ButtonProps & Pick<ButtonHTMLAttributes<HTMLButtonElement>, "title" | "popoverTarget">) {
  return <AstryxButton {...props} />;
}

export function Badge(props: BadgeProps & Pick<HTMLAttributes<HTMLSpanElement>, "title">) {
  return <AstryxBadge {...props} />;
}

export function TextInput(props: TextInputProps & Pick<InputHTMLAttributes<HTMLInputElement>, "spellCheck">) {
  return <AstryxTextInput {...props} />;
}

export function Tab(props: TabProps & Pick<ButtonHTMLAttributes<HTMLButtonElement>, "title">) {
  return <AstryxTab {...props} />;
}
