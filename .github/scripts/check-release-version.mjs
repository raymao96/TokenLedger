import { execFileSync } from 'node:child_process';

const forkTag = /^v(?<upstream>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\.(?<revision>[1-9]\d*)$/;
const upstreamRepo = 'https://github.com/BrianWong05/TokenLedger.git';

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function requireAncestor(commit, tip, message) {
  try {
    git('merge-base', '--is-ancestor', commit, tip);
  } catch (error) {
    if (error.status !== 1) throw error;
    throw new Error(message);
  }
}

function checkVersion(tag, preview) {
  const version = forkTag.exec(tag)?.groups;
  if (!version) throw new Error('Release tags must use vMAJOR.MINOR.PATCH.REVISION with a positive revision.');

  const { upstream, revision } = version;
  const commit = git('rev-parse', preview ? 'HEAD' : `refs/tags/${tag}^{commit}`);
  const app = JSON.parse(git('show', `${commit}:src-tauri/tauri.conf.json`));
  if (app.version !== upstream) {
    throw new Error(`${tag} uses upstream version ${upstream}, but the application version is ${app.version}.`);
  }

  requireAncestor(commit, 'refs/remotes/origin/main', `${tag} must point to a commit on main.`);
  if (preview) {
    console.log(`Verified build preview ${tag} for upstream ${upstream}.`);
    return;
  }

  const tags = git('tag', '--list', 'v*', '--sort=-version:refname').split('\n');
  const [newest, previousTag] = tags.filter(candidate => forkTag.test(candidate));
  if (newest !== tag) throw new Error(`${tag} must be newer than ${newest}.`);

  const previous = previousTag ? forkTag.exec(previousTag).groups : undefined;
  if (previous?.upstream === upstream) {
    const next = BigInt(previous.revision) + 1n;
    if (BigInt(revision) !== next) throw new Error(`The next release tag is v${upstream}.${next}.`);
  } else {
    if (revision !== '1') throw new Error(`The first release for upstream ${upstream} must use v${upstream}.1.`);
    git('fetch', '--no-tags', upstreamRepo, `refs/tags/v${upstream}`);
    requireAncestor('FETCH_HEAD', commit, `Merge upstream v${upstream} into main before publishing ${tag}.`);
  }

  console.log(`Verified release ${tag} for upstream ${upstream}.`);
}

try {
  checkVersion(process.argv[2] ?? '', process.argv[3] === '--preview');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
