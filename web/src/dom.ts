export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing page element: ${id}`);
  return element as T;
}

export function formValue(form: FormData, name: string): string {
  const value = form.get(name);
  if (typeof value !== "string") throw new Error(`Missing text field: ${name}`);
  return value;
}

export function formControl(form: HTMLFormElement, name: string) {
  const element = form.elements.namedItem(name);
  if (!(element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement)) {
    throw new Error(`Missing form control: ${name}`);
  }
  return element;
}
