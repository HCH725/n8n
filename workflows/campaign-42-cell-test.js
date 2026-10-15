#!/usr/bin/env node
/**
 * Deterministic checks for the 42-cell formal campaign orchestration.
 *
 * Run: node workflows/campaign-42-cell-test.js   (exit 0 means every check passed)
 *
 * The workflow JSON is the single source of truth: this file loads the Code
 * nodes from WF-Research-42-cell-campaign.json and runs them with stub helpers.
 * No n8n instance, no SSH, no Qlib run. One end-to-end pass feeds 42 clean
 * synthetic receipts through the real node code and checks the campaign
 * coverage receipt; the remaining cases mutate one cell and must hold.
 *
 * ponytail: one test file on purpose. It checks the frozen identity coverage,
 * the fail-closed binding, the per-cell identity binding, the aggregate
 * coverage/claimability rule, the run-location formula the transport uses, and
 * the absence of any parameter sweep.
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const WORKFLOW = path.join(__dirname, 'WF-Research-42-cell-campaign.json');
const workflow = JSON.parse(fs.readFileSync(WORKFLOW, 'utf8'));

const SOURCE_BLOB_SHA = '8a09f6e642261714ef72872b601b8f679e1f0d30';
const SOURCE_COMMIT = '890da11cb50daadc4d59b7fd58a2e96638b17833';
const RUNTIME_COMMIT = 'bee09f23d938b96c2c1ef82d891aa0abfa171cd0';
const CANDIDATE_PATH = 'donchian-20-10-breakout-btcusdt-1h-2026-10-06.md';
const RESULTS_ROOT = '/results/_validation';
const CELLS_DIR = RESULTS_ROOT + '/formal-cells-round0';

function nodeByName(name) {
  const node = workflow.nodes.find((candidate) => candidate.name === name);
  assert(node, 'missing node: ' + name);
  return node;
}

function codeOf(name) {
  return nodeByName(name).parameters.jsCode;
}

function check(name, condition, extra) {
  console.log((condition ? 'PASS ' : 'FAIL ') + name + (condition ? '' : ' ' + JSON.stringify(extra || '')));
  if (!condition) {
    process.exitCode = 1;
    throw new Error('FAILED: ' + name);
  }
}

function runCode(name, context) {
  // The compiled body is this repository's committed node code, read from the
  // workflow JSON beside this file -- never operator, request or network input.
  // The workflow JSON is the single source of truth for these checks.
  const fn = new Function('$getWorkflowStaticData', '$', '$input', '$json', codeOf(name));
  return fn(context.$getWorkflowStaticData, context.$, context.$input, context.$json);
}

function expectHold(name, fn, fragment) {
  try {
    fn();
    check(name, false, 'expected a HOLD');
  } catch (error) {
    check(name, String(error.message).includes(fragment || 'CAMPAIGN HOLD'), error.message);
  }
}

function contextFor(inputItems, upstream, staticData) {
  const $ = (nodeName) => {
    const entry = upstream[nodeName];
    assert(entry, 'unexpected node reference: ' + nodeName);
    return {
      first: () => entry[0],
      all: () => entry,
      item: entry[0],
    };
  };
  const sd = staticData;
  return {
    $getWorkflowStaticData: () => sd,
    $,
    $input: { first: () => inputItems[0], all: () => inputItems },
    $json: inputItems[0] && inputItems[0].json,
    sd,
  };
}

/** The transport's out_dir formula (research-transport.py out_dir_for).
 * Canonical form: JSON of the four frozen fields, keys sorted, no spaces. */
function outDirShort(frozen) {
  const canonical = JSON.stringify({
    effective_config_sha256: frozen.effective_config_sha256,
    entrypoint_sha256: frozen.entrypoint_sha256,
    qlib_runtime_commit: frozen.qlib_runtime_commit,
    source_blob_sha: frozen.source_blob_sha,
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 12);
}

function hexPad(seed, width) {
  return crypto.createHash('sha256').update(seed).digest('hex').slice(0, width);
}

function cellManifestEntry(cellId) {
  const dir = CELLS_DIR + '/' + cellId;
  const entrypointRef = dir + '/run_cell.entrypoint.py';
  const configRef = dir + '/effective_config.json';
  const frozen = {
    source_blob_sha: SOURCE_BLOB_SHA,
    entrypoint_sha256: hexPad('entrypoint', 64),
    effective_config_sha256: hexPad('config:' + cellId, 64),
    qlib_runtime_commit: RUNTIME_COMMIT,
  };
  const outDir = RESULTS_ROOT + '/n8n-live-' + outDirShort(frozen);
  return {
    cell_id: cellId,
    symbol: cellId.split('-')[0],
    timeframe: cellId.split('-')[1],
    research_leverage: Number(cellId.split('-')[2].slice(1)),
    source_commit: SOURCE_COMMIT,
    candidate_path: CANDIDATE_PATH,
    source_blob_sha: SOURCE_BLOB_SHA,
    entrypoint_ref: entrypointRef,
    entrypoint_sha256: frozen.entrypoint_sha256,
    effective_config_ref: configRef,
    effective_config_sha256: frozen.effective_config_sha256,
    qlib_runtime_commit: RUNTIME_COMMIT,
    capabilities: { execution: ['qlib-native-backtest'], data: ['btcusdt-1h'], timing: ['bar-close-1h'] },
    evidence_refs: {
      candidate: 'https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/' + SOURCE_BLOB_SHA,
      manifest: outDir + '/manifest.json',
      mlflow_readback: outDir + '/mlflow_readback.json',
    },
    research_cost_model: { fees_per_side: 0.0004, slippage: 0.0, funding: 'not_modeled', approved: true },
    run_inputs: { symbol: cellId.split('-')[0], timeframe: cellId.split('-')[1], research_leverage: Number(cellId.split('-')[2].slice(1)) },
  };
}

function campaignManifest(ids) {
  return { schema: 'qlib-formal-campaign-manifest-v1', cell_count: ids.length, cells: ids.map(cellManifestEntry) };
}

function cleanSubmitReceipt(handoff) {
  return {
    node04: 'PASS',
    candidate_path: handoff.candidate_path,
    candidate_blob_sha: handoff.source_blob_sha,
    entrypoint_sha256: handoff.entrypoint_sha256,
    effective_config_sha256: handoff.effective_config_sha256,
    run_id: hexPad('run:' + handoff.effective_config_sha256, 32),
    experiment_id: '640215677191042801',
    out_dir: handoff.evidence_refs.manifest.replace('/manifest.json', ''),
    status: 'FINISHED',
    cost_declared: true,
  };
}

function cleanReadbackReceipt(shell, handoff) {
  const submitted = shell.node04_receipt;
  return {
    node05: 'PASS',
    run_id: submitted.run_id,
    experiment_id: submitted.experiment_id,
    candidate_path: handoff.candidate_path,
    candidate_blob_sha: handoff.source_blob_sha,
    status: 'FINISHED',
    params_count: 6,
    metrics_count: 3,
    artifacts_count: 5,
    out_dir: submitted.out_dir,
    refs: {
      candidate: 'https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/' + handoff.source_blob_sha,
      mlflow_run: submitted.out_dir + '/mlruns/' + submitted.experiment_id + '/' + submitted.run_id,
      mlflow_readback: handoff.evidence_refs.mlflow_readback,
      manifest: handoff.evidence_refs.manifest,
      effective_config: handoff.effective_config_ref,
      entrypoint: handoff.entrypoint_ref,
    },
    readable: { candidate: true, data: true, execution: true, runtime: true, evidence: true },
    manifest_verified: true,
    manifest_readback_run_id: submitted.run_id,
    manifest_sha256: hexPad('manifest:' + submitted.run_id, 64),
    coverage_complete: false,
    performance_claimable: false,
  };
}

/** Run the whole campaign in process over a manifest; return the campaign receipt. */
function runCampaign(manifest, mutateReadback) {
  const sd = {};
  const identities = runCode('01 · Generate 42 cell identities', contextFor([], {}, sd));
  const bound = runCode('02 · Bind frozen cell handoffs', contextFor(identities, {
    '01 · Campaign input': [{ json: { campaign_manifest: JSON.stringify(manifest), market_data_ready: true } }],
  }, sd));
  for (const item of bound) {
    const handoff = item.json.executable_handoff;
    const sshSubmit = { json: { code: 0, stdout: JSON.stringify(cleanSubmitReceipt(handoff)), stderr: '' } };
    const shell = runCode('05 · Verify cell submit receipt', contextFor([sshSubmit], {
      '03 · Loop over 42 cells': [item],
    }, sd))[0];
    const readback = cleanReadbackReceipt(shell.json, handoff);
    if (mutateReadback) mutateReadback(readback, shell.json);
    const sshReadback = { json: { code: 0, stdout: JSON.stringify(readback), stderr: '' } };
    runCode('07 · Verify cell readback', contextFor([sshReadback], {
      '05 · Verify cell submit receipt': [shell],
    }, sd));
  }
  const campaign = runCode('08 · Campaign coverage aggregate', contextFor([{ json: {} }], {}, sd))[0].json;
  return { campaign, bound, sd };
}

function main() {
  // T1 structure
  check('workflow JSON parses with 10 nodes', workflow.nodes.length === 10, workflow.nodes.length);
  const names = workflow.nodes.map((node) => node.name);
  check('node names are unique', new Set(names).size === names.length);
  for (const [source, outputs] of Object.entries(workflow.connections)) {
    assert(names.includes(source), 'unknown source ' + source);
    for (const branch of outputs.main) {
      for (const target of branch) check('connection target exists: ' + target.node, names.includes(target.node));
    }
  }
  const loop = nodeByName('03 · Loop over 42 cells');
  check('one native Loop Over Items node drives the campaign', loop.type === 'n8n-nodes-base.splitInBatches');
  check('SSH submit uses the frozen research-submit verb',
    /^=\{\{ 'research-submit ' \+ \$json\.transport_payload_b64 \}\}$/.test(nodeByName('04 · Submit cell to Qlib').parameters.command));
  check('SSH readback uses the frozen research-readback verb',
    /^=\{\{ 'research-readback ' \+ \$\('05 · Verify cell submit receipt'\)\.item\.json\.qlib_run_id \}\}$/
      .test(nodeByName('06 · Read back cell artifacts').parameters.command));
  const code = workflow.nodes.map((node) => codeOf(node.name))
    .join('\n')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, ''))
    .join('\n');
  for (const forbidden of ['gridSearch', 'optimizer(', 'parameterSweep', 'param_grid', 'itertools', 'cartesian'])
    check('no parameter sweep construct: ' + forbidden, !code.includes(forbidden));

  // T2 frozen identity coverage
  const sd0 = {};
  const identities = runCode('01 · Generate 42 cell identities', contextFor([], {}, sd0));
  const ids = identities.map((item) => item.json.cell_id);
  check('generator emits exactly 42 identities', ids.length === 42, ids.length);
  check('identities are unique', new Set(ids).size === 42);
  const expected = [];
  for (const symbol of ['BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'XRPUSDT', 'DOGEUSDT', 'LINKUSDT'])
    for (const timeframe of ['1h', '4h', '1d'])
      for (const leverage of [3, 5]) expected.push(symbol + '-' + timeframe + '-x' + leverage);
  check('identities are the frozen cross product 7x3x2', ids.join(',') === expected.join(','));
  check('generator is stable across calls',
    runCode('01 · Generate 42 cell identities', contextFor([], {}, {})).map((item) => item.json.cell_id).join(',') === ids.join(','));

  // T3 run-location formula matches the transport and the deployed evidence
  check('out_dir formula reproduces the deployed representative evidence dir',
    outDirShort({
      source_blob_sha: SOURCE_BLOB_SHA,
      entrypoint_sha256: '000e23b739eb13a7c3b1077af5501556bd73fd2ec0e9d439ce1e6d5113d14c05',
      effective_config_sha256: '7a976cce5a6d418c635af073e9df7f553b6893259c79e59722f49b368c28d1d2',
      qlib_runtime_commit: RUNTIME_COMMIT,
    }) === '8b37e4ca2140');

  // T4 clean campaign: 42/42 PASS + declared approved cost -> coverage and claimability
  const clean = runCampaign(campaignManifest(expected));
  check('clean campaign bounds 42 cells', clean.bound.length === 42, clean.bound.length);
  check('bound handoffs are unique run locations',
    new Set(clean.bound.map((item) => item.json.executable_handoff.effective_config_sha256)).size === 42);
  check('clean campaign records 42 cells', clean.sd.campaign_records.length === 42, clean.sd.campaign_records.length);
  check('clean campaign coverage is complete', clean.campaign.coverage_complete === true, clean.campaign);
  check('clean campaign evidence is complete', clean.campaign.evidence_complete === true);
  check('clean campaign is performance claimable', clean.campaign.performance_claimable === true, clean.campaign);
  check('clean campaign passes the gate', clean.campaign.route === 'PASS' && clean.campaign.gaps.length === 0);
  const record = clean.sd.campaign_records[0];
  for (const key of ['symbol', 'timeframe', 'research_leverage', 'effective_config_sha256', 'qlib_run_id', 'experiment_id'])
    check('cell record exposes ' + key, record[key] !== undefined && record[key] !== null);
  check('cell record carries the Node05 PASS fact', record.node05_pass === true);
  runCode('09 · Campaign gate', contextFor([{ json: clean.campaign }], {}, clean.sd));

  // T5 held campaigns
  expectHold('41 cells hold at binding', () => runCampaign(campaignManifest(expected.slice(0, 41))), 'covers 41 of 42');

  const duplicated = campaignManifest(expected);
  duplicated.cells[41] = JSON.parse(JSON.stringify(duplicated.cells[0]));
  expectHold('duplicate manifest cell holds', () => runCampaign(duplicated), 'duplicate cell');

  const mismatched = campaignManifest(expected);
  mismatched.cells[6].symbol = 'ADAUSDT';
  expectHold('identity mismatch holds', () => runCampaign(mismatched), 'identity mismatch');

  const sharedRun = campaignManifest(expected);
  sharedRun.cells[1].effective_config_sha256 = sharedRun.cells[0].effective_config_sha256;
  expectHold('two cells sharing one run location hold', () => runCampaign(sharedRun), 'shares one run location');

  const forged = campaignManifest(expected);
  forged.cells[3].entrypoint_sha256 = 'zz';
  expectHold('forged executable hash holds', () => runCampaign(forged), 'invalid entrypoint binding');

  expectHold('a cell with unreadable evidence holds before the aggregate',
    () => runCampaign(campaignManifest(expected), (readback) => { readback.readable.execution = false; }),
    'unreadable execution');

  expectHold('a cell with a failed manifest holds before the aggregate',
    () => runCampaign(campaignManifest(expected), (readback, shell) => {
      if (shell.cell_id === expected[10]) readback.manifest_verified = false;
    }), 'manifest or run identity');

  const unapproved = campaignManifest(expected);
  for (const cell of unapproved.cells) cell.research_cost_model.approved = false;
  const unapprovedRun = runCampaign(unapproved);
  check('unapproved research cost keeps coverage complete', unapprovedRun.campaign.coverage_complete === true);
  check('unapproved research cost blocks claimability',
    unapprovedRun.campaign.performance_claimable === false && unapprovedRun.campaign.route === 'HOLD',
    unapprovedRun.campaign);
  expectHold('unapproved research cost holds at the gate',
    () => runCode('09 · Campaign gate', contextFor([{ json: unapprovedRun.campaign }], {}, unapprovedRun.sd)),
    'not claimable');

  // T6 aggregate-level rejection of an incomplete or duplicated ledger
  const partial = runCampaign(campaignManifest(expected));
  partial.sd.campaign_records.pop();
  const partialCampaign = runCode('08 · Campaign coverage aggregate', contextFor([{ json: {} }], {}, partial.sd))[0].json;
  check('aggregate refuses a 41-cell ledger',
    partialCampaign.coverage_complete === false && partialCampaign.route === 'HOLD'
    && partialCampaign.gaps.some((gap) => gap.startsWith('missing cell')), partialCampaign.gaps);
  const dup = runCampaign(campaignManifest(expected));
  dup.sd.campaign_records.push(JSON.parse(JSON.stringify(dup.sd.campaign_records[0])));
  const dupCampaign = runCode('08 · Campaign coverage aggregate', contextFor([{ json: {} }], {}, dup.sd))[0].json;
  check('aggregate refuses a duplicated cell',
    dupCampaign.coverage_complete === false && dupCampaign.gaps.some((gap) => gap.startsWith('duplicate cell')),
    dupCampaign.gaps);
  const extra = runCampaign(campaignManifest(expected));
  extra.sd.campaign_records.push({
    campaign_run_key: extra.sd.campaign_run_key, cell_id: 'BTCUSDT-1h-x4', symbol: 'BTCUSDT', timeframe: '1h',
    research_leverage: 4, effective_config_sha256: hexPad('config:extra', 64), entrypoint_sha256: hexPad('entrypoint', 64),
    qlib_run_id: hexPad('run:extra', 32), experiment_id: '1', out_dir: RESULTS_ROOT + '/n8n-live-extra',
    receipt_sha256: hexPad('manifest:extra', 64), node05_pass: true, evidence_complete: true, cost_declared: true,
    cost_model_approved: true,
  });
  const extraCampaign = runCode('08 · Campaign coverage aggregate', contextFor([{ json: {} }], {}, extra.sd))[0].json;
  check('aggregate refuses a 43rd cell',
    extraCampaign.coverage_complete === false && extraCampaign.gaps.some((gap) => gap.startsWith('unknown cell')),
    extraCampaign.gaps);
  const foreign = runCampaign(campaignManifest(expected));
  foreign.sd.campaign_records.forEach((record) => { record.campaign_run_key = 'other-run'; });
  const foreignCampaign = runCode('08 · Campaign coverage aggregate', contextFor([{ json: {} }], {}, foreign.sd))[0].json;
  check('aggregate ignores records from another campaign run',
    foreignCampaign.observed_cells === 0 && foreignCampaign.coverage_complete === false, foreignCampaign);

  console.log('ALL 42-CELL CAMPAIGN CHECKS PASSED');
}

main();
