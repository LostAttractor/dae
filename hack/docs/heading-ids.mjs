import { visit } from 'unist-util-visit';

export default function headingIds() {
  return (tree) => {
    visit(tree, 'heading', (node) => {
      const value = node.children.at(-1)?.value;
      if (typeof value !== 'string' || !value.endsWith('}')) return;

      const start = value.lastIndexOf('{#');
      if (start === -1) return;
      const id = value.slice(start + 2, -1);
      if (!id || /[}\r\n\u2028\u2029]/u.test(id)) return;

      // remark-validate-links reads explicit IDs from heading node data.
      node.data ??= {};
      node.data.id = id;
    });
  };
}
