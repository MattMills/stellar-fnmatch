#!/usr/bin/env python3
"""Compare stellar-fnmatch labels of Steam builds with the existing fn2hash translation in the
stellar-fnaddr database (read only), for the versions the database covers.

The existing translator maps a Steam function (a Ghidra function in fn2hash) to a GOG function
with an equal hash, trying pic_hash, composite_pic_hash, mnemonic_hash, mnemonic_count_hash,
mnemonic_category_hash, mnemonic_category_count_hash in that order and taking the first row
(arbitrary when several GOG functions share the hash). The GOG function's symbol is the answer.

stellar-fnmatch labels name the function; the name is turned into a GOG address through the GOG
build's own PDB names (`stellar-fnmatch info --dump-names`), so both answers are compared as GOG
addresses.

  python3 -I compare_fn2hash.py --labels runs/X/labels --export runs/X/export.csv \
      --gog-names-dir dbcmp/gognames --out dbcmp/report.json
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import subprocess

HASHES = ['pic_hash', 'composite_pic_hash', 'mnemonic_hash', 'mnemonic_count_hash',
          'mnemonic_category_hash', 'mnemonic_category_count_hash']
BASE = 0x140000000


def psql(sql):
    out = subprocess.run(['psql', '-U', 'postgres', '-d', 'stellar-fnaddr', '-At', '-F', '\t', '-c', sql],
                         check=True, capture_output=True, text=True).stdout
    return [line.split('\t') for line in out.splitlines() if line]


def load_labels(path):
    out = {}
    with open(path, newline='') as fh:
        for row in csv.DictReader(fh):
            if row['label']:
                out[int(row['rva'], 16)] = row['label'].split(' | ')
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--labels', required=True)
    ap.add_argument('--export', help='export.csv of the same run (build id <-> exe md5); computed from corpus.json when absent')
    ap.add_argument('--gog-names-dir', required=True, help='<gog build id>.tsv from info --dump-names')
    ap.add_argument('--corpus', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    corpus = json.load(open(a.corpus))['builds']
    md5_to_build = {}
    if a.export:
        with open(a.export, newline='') as fh:
            for row in csv.DictReader(fh):
                md5_to_build[row['exe_md5']] = row['build_id']
    else:
        db_versions = {r[0] for r in psql('select distinct version from versions')}
        for b in corpus:
            if b['platform'] == 'steam' and b['version'] in db_versions:
                h = hashlib.md5()
                with open(b['exe_path'], 'rb') as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b''):
                        h.update(chunk)
                md5_to_build[h.hexdigest()] = b['id']

    versions = psql("select id, version, platform, md5 from versions where os = 'windows' order by id")
    by_ver = collections.defaultdict(dict)
    for vid, ver, plat, md5 in versions:
        by_ver[ver][plat] = (int(vid), md5)
    seen_md5 = collections.Counter(md5 for _, _, plat, md5 in versions if plat == 'steam')

    report = {}
    for ver, plats in sorted(by_ver.items()):
        if 'steam' not in plats or 'gog' not in plats:
            continue
        svid, smd5 = plats['steam']
        gvid, _ = plats['gog']
        if seen_md5[smd5] > 1:
            report[ver] = {'skipped': 'steam md5 listed for several versions'}
            continue
        sbuild = md5_to_build.get(smd5)
        gogs = [b['id'] for b in corpus if b['platform'] == 'gog' and b['version'] == ver and b['pdb_path']]
        if not sbuild or not gogs:
            report[ver] = {'skipped': 'no matching build (steam %s, gog %s)' % (sbuild, gogs)}
            continue
        gbuild = gogs[0]
        names_to_rva = collections.defaultdict(set)
        with open(os.path.join(a.gog_names_dir, gbuild + '.tsv')) as fh:
            for line in fh:
                rva, names = line.rstrip('\n').split('\t', 1)
                for n in names.split(' | '):
                    names_to_rva[n].add(int(rva, 16))
        ours = load_labels(os.path.join(a.labels, sbuild + '.csv'))

        cols = ', '.join(HASHES)
        steam = psql('select addr, %s, num_instructions from fn2hash where version_id = %d' % (cols, svid))
        gog = psql('select addr, %s from fn2hash where version_id = %d' % (cols, gvid))
        gsym_name = {int(r[0]): r[1] for r in psql('select sa.addr, s.symbol from symbol_addr sa join symbols s on s.id = sa.symbol_id where sa.version_id = %d' % gvid)}
        gsym = set(gsym_name)
        index = [collections.defaultdict(list) for _ in HASHES]
        for r in gog:
            for k in range(len(HASHES)):
                index[k][r[1 + k]].append(int(r[0]))

        c = collections.Counter()
        samples = collections.defaultdict(list)
        disagreements = []
        agreed = []  # (steam va, gog va) where both methods give the same unique answer
        for r in steam:
            addr = int(r[0])
            c['steam_functions'] += 1
            cands = []
            for k in range(len(HASHES)):
                cands = [g for g in index[k].get(r[1 + k], []) if g in gsym]
                if cands:
                    break
            label = ours.get(addr - BASE)
            our_gog = set()
            if label:
                for n in label:
                    our_gog |= {BASE + x for x in names_to_rva.get(n.split(' [')[0], ())}
            if cands:
                c['existing_answered'] += 1
                c['existing_unique' if len(cands) == 1 else 'existing_ambiguous'] += 1
            if label:
                c['ours_answered'] += 1
            funclet_parent = None
            if label and label[0].endswith((' [unwind funclet]', ' [catch funclet]')):
                funclet_parent = label[0].rsplit(' [', 1)[0]
            if cands and label and funclet_parent is not None:
                # the existing method names the funclet itself ("`Parent'::`1'::dtor$N")
                if any(gsym_name.get(g, '').startswith('`%s\'::' % funclet_parent) for g in cands):
                    c['funclet_same_parent'] += 1
                else:
                    c['funclet_other_parent'] += 1
            elif cands and label:
                if our_gog & set(cands):
                    c['agree' if len(cands) == 1 else 'agree_with_one_of_ambiguous'] += 1
                    if len(cands) == 1:
                        agreed.append((addr, cands[0]))
                elif not our_gog:
                    c['ours_name_not_in_gog'] += 1
                else:
                    key = 'disagree_existing_unique' if len(cands) == 1 else 'disagree_existing_ambiguous'
                    c[key] += 1
                    disagreements.append((key, addr, cands, sorted(our_gog)))
                    if len(samples[key]) < 15:
                        samples[key].append({'steam_va': hex(addr), 'existing_gog_va': [hex(x) for x in cands[:3]],
                                             'ours': label, 'ours_gog_va': [hex(x) for x in sorted(our_gog)[:3]]})
            elif label:
                c['only_ours'] += 1
            elif cands:
                c['only_existing'] += 1
                c['only_existing_unique' if len(cands) == 1 else 'only_existing_ambiguous'] += 1
                ninsn = int(r[-1])
                c['only_existing_le5insn' if ninsn <= 5 else 'only_existing_gt5insn'] += 1
            else:
                c['neither'] += 1
        # Adjudicate disagreements by layout: the Steam and GOG builds of one version are the same
        # commit and keep function order, so the Steam->GOG address offset changes slowly. The
        # local offset is the median over the 20 nearest agreed functions; an answer "fits" when
        # it lands within 0x2000 of where that offset puts the function.
        agreed.sort()
        keys = [s for s, _ in agreed]
        import bisect
        for key, addr, cands, ours_g in disagreements:
            i = bisect.bisect_left(keys, addr)
            near = agreed[max(0, i - 10):i + 10]
            if not near:
                continue
            offs = sorted(g - s for s, g in near)
            expect = addr + offs[len(offs) // 2]
            fits_ours = any(abs(g - expect) < 0x2000 for g in ours_g)
            fits_existing = any(abs(g - expect) < 0x2000 for g in cands)
            c[key + ('_ours_fits' if fits_ours else '') + ('_existing_fits' if fits_existing else '') + ('' if fits_ours or fits_existing else '_neither_fits')] += 1
        # all functions of the Steam build in stellar-fnmatch's function list
        c['fnmatch_functions'] = sum(1 for _ in open(os.path.join(a.labels, sbuild + '.csv'))) - 1
        c['fnmatch_labelled'] = len(ours)
        report[ver] = {'steam_build': sbuild, 'gog_build': gbuild, 'counts': dict(c), 'samples': samples}
        print(ver, sbuild, gbuild, dict(c))
    json.dump(report, open(a.out, 'w'), indent=1)


if __name__ == '__main__':
    main()
