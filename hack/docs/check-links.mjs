import { remark } from 'remark';
import { engine } from 'unified-engine';

// Use the same file/configuration engine as remark-cli without its watch mode.
engine({
  processor: remark,
  files: process.argv.slice(2),
  extensions: ['md', 'markdown', 'mdown', 'mkdn', 'mkd', 'mdwn', 'mkdown', 'ron'],
  pluginPrefix: 'remark',
  packageField: 'remarkConfig',
  rcName: '.remarkrc',
  ignoreName: '.remarkignore',
  quiet: true,
  frail: true,
  out: false,
}, (error, code) => {
  if (error) console.error(error);
  process.exitCode = error ? 1 : code;
});
