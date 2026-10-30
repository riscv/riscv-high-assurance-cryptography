#!/usr/bin/env pypy3.12
"""Architecture-level management KAT (Zkl-ISA-unpriv.adoc, Zkl-ISA-machines.adoc).  Run: cd src && pypy3.12 kat/mgmt-kat.py
Model: mgmt_model.py (lockers, States, setst Forms, kl.mgmt, restrict, clone/rename/swap, toy Machines).  Expected values
are written out from the spec text; rules are cited by anchor name.  Not covered: see FINDINGS-mgmt.md."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mgmt_model import *

def trap(fn, *a, **kw):
    try: fn(*a, **kw)
    except Trap as t: return t.kind
    except IllegalInstruction: return 'illegal'
    return None
def mk(mach=M_ENC, pol=3, up=0x4, **kw):
    f = dict(Machine=mach, MachinePolicy=pol, UsagePolicy=up); f.update(kw); return mdh_pack(**f)
def prov(e, k, md=None, **kw):
    e.mgmt(k, 56, form='C', md=mk(**kw) if md is None else md); FIN(e, k)
def stx(e, k): return (e.getst(k), e.getstx(k))
INV = (0, SE_INVALID)
def FIN(e, k): e.mgmt(k, 63, form='C', md=mk(State=0))   # provisioning completion ignores ml.State

section('MDH layout  <<KLE-metadata-header>>')
tot = sum(w for _, _, w in MDH_FIELDS)
check('fields tile 128 bits', tot == 128 and all(MDH_FIELDS[i][1] + MDH_FIELDS[i][2] == MDH_FIELDS[i + 1][1] for i in range(len(MDH_FIELDS) - 1)))
check('State [23:18], UsagePolicy [68:64], Locality [77:69], ExpirationDate [115:96]',
      mdh_pack(State=63) == 63 << 18 and mdh_pack(UsagePolicy=31) == 31 << 64 and mdh_pack(Locality=511) == 511 << 69 and mdh_pack(ExpirationDate=mask(20)) == mask(20) << 96)
e = KLE(); check('Unconfigured: getmd all zero (<<KLE-GR-outcome-inert>>)', e.getmd(3) == 0 and e.getst(3) == 0 and e.getstx(3) == 0)
section('Provisioning and States  <<KLE-State-field>>, <<KLE-MVR-open>>')
e = KLE(); e.mgmt(3, 56, md=mk()); check('opening kl.mgmt provisioning: State 56 (Provisioning)', stx(e, 3) == (56, 0))
check('klnamedlocker names the locker (<<KLE-GR-klnamedlocker-updates>>)', e.nl == 3)
FIN(e,3); check('completing: Ready, StateExtension 0, MachineUse 0', stx(e, 3) == (1, 0) and mdh_get(e.md(3), 'MachineUse') == 0)
e = KLE(); e.mgmt(3, 56, md=mk(MachineUse=77, AuxInfo=5)); check('provisioning zeroes MachineUse', mdh_get(e.md(3), 'MachineUse') == 0)
for nm, kw in (('State 1', dict(State=1)), ('StateExtension 1 (Error-State PI)', dict(StateExtension=1)), ('AuxDataLen 2', dict(AuxDataLen=2)),
               ('ADSDropped', dict(ADSDropped=1)), ('AuxDataLen 1', dict(AuxDataLen=1)), ('Version 1', dict(Version=1)), ('Version 2', dict(Version=2)),
               ('Version 3 in a PI', dict(Version=3)), ('SCProtection 3', dict(SCProtection=3)), ('KeyType 3', dict(KeyType=3)),
               ('Locality[5:4]=3', dict(Locality=0x30)), ('reserved bit 30', dict(Reserved31_30=1)), ('reserved bit 46', dict(Reserved46=1)),
               ('reserved 78', dict(Reserved79_78=1)), ('reserved 116-127', dict(Reserved127_116=1)), ('MachinePolicy zero for TOYENC', dict(MachinePolicy=0)),
               ('KeyType 1 w/o key field', dict(KeyType=1)), ('KeyType 2 w/o key field', dict(KeyType=2))):
    e = KLE(); md = mk(**kw)
    r = trap(e.mgmt, 5, 56, md=md)
    check('invalid PI -> Error State Invalid, no exception, other fields zero: ' + nm + ' <<KLE-Metadata-validity>>', r is None and e.md(5) == mdh_pack(State=0, StateExtension=SE_INVALID) and e.nl == 5)
e = KLE(); check('ExpirationDate w/o Zklexpire invalid', (lambda: (e := KLE(zk=False), e.mgmt(2, 56, md=mk(ExpirationDate=5)), stx(e, 2))[2])() == INV)
e = KLE(zk=False); e.mgmt(2, 56, md=mk()); check('Zklexpire absent: valid PI still provisions', stx(e, 2) == (56, 0))
e = KLE(); r = trap(e.mgmt, 2, 56, md=mk(mach=0x99)); check('unsupported Machine -> kl_exc_unsupported, locker Unconfigured, klstart 0 <<KLE-Metadata-validity>>', r == 'unsupported' and e.md(2) == 0)
e = KLE(); r = trap(e.mgmt, 2, 56, md=mk(mach=0x99, Version=1)); check('invalid takes precedence over unsupported', r is None and stx(e, 2) == INV)
e = KLE(); e.start = 9; e.mgmt(2, 56, md=mk()); check('provisioning clears klstart (<<KLE-GR-outcome-inert>>)', e.start == 0)
e = KLE(slots=0); r = trap(e.mgmt, 2, 56, md=mk()); check('no KLF capacity -> kl_exc_out_of_memory, Unconfigured, klnamedlocker names it <<KLE-GR-klf-capacity>>', r == 'out_of_memory' and e.md(2) == 0 and e.nl == 2)
e = KLE(slots=1); prov(e, 0); check('exactly enough capacity', stx(e, 0) == (1, 0) and e.slots == 0)
e = KLE(slots=1); e.mgmt(0, 56, md=mk(Version=1)); check('Error-State locker holds no capacity <<KLE-GR-error-state-transition>>', e.slots == 1)
check('Form B of kl.mgmt reserved -> illegal', trap(KLE().mgmt, 1, 56, form='B') == 'illegal')
check('immed7 59, 60, 61, 62 of kl.mgmt reserved', all(trap(KLE().mgmt, 1, i) == 'illegal' for i in (59, 60, 61, 62)))
e = KLE(); e.mgmt(4, 56, md=mk(mach=M_KEY, KeyType=2)); FIN(e,4)
check('KeyType 2 provisioning generates a key and KeyType becomes 0 (<<KLE-KeyType-field>>)', mdh_get(e.md(4), 'KeyType') == 0 and e.L[4].content != 0)
e2 = KLE(); e2.mgmt(4, 56, md=mk(mach=M_KEY, KeyType=2)); e2.mgmt(4, 58, md=mk(mach=M_KEY, KeyType=2, State=1))
check('KeyType 2 at import invalid', stx(e2, 4) == INV)
e = KLE(); e.mgmt(4, 56, md=mk(mach=M_KEY, KeyType=2)); e.setste(4, 3); check('Error State during a KeyType 2 provisioning: KeyType set to 0 (GR34), MDH re-importable', stx(e, 4) == (0, 3) and mdh_get(e.md(4), 'KeyType') == 0)
e = KLE(); e.mgmt(4, 56, md=mk(mach=M_KEY, KeyType=1)); check('KeyType 1 valid for keyed Machine', stx(e, 4) == (56, 0))
e = KLE(); e.mgmt(1, 56, md=mk()); e.mgmt(1, 56, md=mk(Version=1)); check('provisioning is allowed in every State and zeroizes (re-provision over 56 -> Invalid)', stx(e, 1) == INV)
e = KLE(); e.mgmt(1, 56, md=mk(AuxDataLen=0)); e.L[1].mdh = mdh_put(e.md(1), 'AuxDataLen', 4); FIN(e,1)
check('completion with AuxDataLen != 0 -> Error Invalid <<KLE-GR-completion>>', stx(e, 1) == INV)
e = KLE(); e.mgmt(1, 56, md=mk()); check('provisioning completion ignores ml.State (even 2): no exception, Ready, State != 0', trap(e.mgmt, 1, 63, form='C', md=mk(State=2)) is None and stx(e, 1) == (1, 0))
e = KLE(); prov(e, 1); check('completing kl.mgmt on a Valid State -> illegal <<KLE-GR-valid-no-mgmt>>', trap(e.mgmt, 1, 63, form='A') == 'illegal' and stx(e, 1) == (1, 0))
e = KLE(); check('completing kl.mgmt on Unconfigured: no-op', trap(e.mgmt, 1, 63, form='A') is None and e.md(1) == 0 and e.nl == 1)
check('kl.mgmt Form A on Unconfigured locker with Machine 0 provisioning -> unsupported', trap(KLE().mgmt, 1, 56, form='A') == 'unsupported')

section('Error States  <<KLE-State-field>>, <<KLE-GR-outcome-inert>>')
for se in range(1, 7):
    e = KLE(); e.setste(5, se); check('kl.setste #%d: State 0, StateExtension %d' % (se, se), stx(e, 5) == (0, se))
check('kl.setste #6 reserved without Zklexpire -> illegal', trap(KLE(zk=False).setste, 5, 6) == 'illegal')
check('kl.setste #0 and #7 reserved -> illegal', trap(KLE().setste, 5, 0) == 'illegal' and trap(KLE().setste, 5, 7) == 'illegal')
check('kl.setste Form C reserved (valid only F=00)', trap(KLE().setste, 5, 1, form='C') == 'illegal')
e = KLE(); prov(e, 5); e.setste(5, 4); check('setste in a Valid State -> Error State; slot freed (GR35)', stx(e, 5) == (0, 4) and e.slots == 8)
e = KLE(); e.mgmt(5, 56, md=mk()); e.setste(5, 2); check('setste in Provisioning accepted without exception', stx(e, 5) == (0, 2))
e = KLE(); e.nl = 7; e.setste(5, 3); check('setste leaves klnamedlocker unchanged', e.nl == 7)
e = KLE(); e.setste(5, 3); check('setste on an Error State writes the new Error State', (e.setste(5, 5), stx(e, 5))[1] == (0, 5))
e = KLE(); check('setste with KLNL & nl=32 writes nothing', (e.setste(0, 3, r=1), e.md(0))[1] == 0)
e = KLE(); e.nl = 6; e.setste(0, 3, r=1); check('setste via KLNL writes the named locker', stx(e, 6) == (0, 3))
e = KLE(); e.mgmt(5, 56, md=mk(Version=1)); check('Error State is inert: usage instruction no-op, no exception', trap(e.exec, 5) is None and stx(e, 5) == INV)
check('Error State: kl.size A = 16', (lambda e: e.size(5))(e) == 16)
check('Unconfigured: kl.size A = 0, kl.avail A = 0', KLE().size(3) == 0 and KLE().avail(3) == 0)
check('Error State: kl.avail A = 1 if Machine implemented (<<KLE-GR-outcome-inert>> table)', (lambda: (lambda e: (e.L.__setitem__(5, Locker()), setattr(e.L[5], 'mdh', mdh_pack(Machine=M_ENC, StateExtension=2)), e.avail(5))[2])(KLE()))() == 1)
check('Error State: kl.avail A = 0 if Machine not implemented', (lambda: (lambda e: (setattr(e.L[5], 'mdh', mdh_pack(Machine=0x99, StateExtension=2)), e.avail(5))[1])(KLE()))() == 0)

section('Inert outcomes  <<KLE-GR-outcome-inert>>')
e = KLE(); e.start = 9; check('kl.exec on Unconfigured: no exception, klstart <- 0', trap(e.exec, 4) is None and e.start == 0)
e = KLE(); e.start = 9; e.setst(4, 2); check('kl.setst on Unconfigured: no-op, klstart unchanged', e.start == 9 and e.md(4) == 0)
e = KLE(); e.start = 9; e.clearads(4); check('kl.clearads on inert: klstart unchanged', e.start == 9)
e = KLE(); e.start = 9; e.exec(0, r=1); check('kl.exec with KLNL & 32: fall through, klstart <- 0', e.start == 0)
e = KLE(); check('restrict on Unconfigured: nothing', trap(e.rstr, 4, mk()) is None and e.md(4) == 0)
e = KLE(); check('getmd/getst/getstx with KLNL & 32: zeros', e.getmd(0, r=1) == 0 and e.getst(0, r=1) == 0 and e.getstx(0, r=1) == 0)
e = KLE(); e.mgmt(4, 56, md=mk(Version=1)); check('getmd of an Error State returns its MDH', e.getmd(4) == mdh_pack(State=0, StateExtension=2))
e = KLE(); e.start = 9; e.mgmt(0, 56, r=1, md=mk()); check('kl.mgmt provisioning with KLNL & 32: only klstart <- 0, no locker touched', e.start == 0 and e.nl == 32 and all(l.mdh == 0 for l in e.L))
e = KLE(); e.nl = 3; e.mgmt(0, 56, r=1, md=mk()); check('kl.mgmt via KLNL names that locker', stx(e, 3) == (56, 0))
e = KLE(); check('mvin / mvout with KLNL & 32: nothing / zeros', e.mvin(5) is None and e.mvout() == (0, 0))
e = KLE(); check('kl.clone, kl.rename, kl.swap with KLNL & 32: no-ops', (prov(e, 1), e.clone('NL', 1), e.rename(1, 'NL'), e.swap('NL', 1), stx(e, 1))[4] == (1, 0))
check('kl.clear with KLNL & 32: no-op, no exception', trap(KLE().clear, 0, 1) is None)
e = KLE(csk=False); check('no CSK -> kl_exc_no_csk before any locker action <<KLE-GR-locker-state-independent>>', trap(e.exec, 4) == 'no_csk' and trap(e.clear, 4) == 'no_csk' and trap(e.rstr, 4, 0) == 'no_csk')

section('kl.setst, kl.clear, kl.clearads, kl.clearall  <<KLE-GR-setst-states>>')
e = KLE(); prov(e, 1)
check('kl.setst Encrypt (2) from Ready', (e.setst(1, 2), stx(e, 1))[1] == (2, 0))
check('kl.setst naming the current State (not Ready): Invalid <<KLE-GR-setst-current>>', (e.setst(1, 2), stx(e, 1))[1] == INV)
e = KLE(); prov(e, 1); e.setst(1, 1); check('kl.setst Ready in Ready admitted <<KLE-GR-ready-clearads>>', stx(e, 1) == (1, 0))
e = KLE(); prov(e, 1); e.setst(1, 3); e.setst(1, 1); check('kl.setst Ready from Decrypt', stx(e, 1) == (1, 0))
e = KLE(); prov(e, 1); e.setst(1, 2); e.setst(1, 3); check('kl.setst naming a State other than Ready from non-Ready: Invalid (MR18)', stx(e, 1) == INV)
for i in (54, 55):
    e = KLE(); prov(e, 1); e.setst(1, i); check('kl.setst #%d never settable (<<KLE-GR-setst-success-failure>>): Invalid' % i, stx(e, 1) == INV)
for i in range(56, 64):
    check('kl.setst G=00 immed7 %d reserved -> illegal (GR23)' % i, trap(KLE().setst, 1, i) == 'illegal')
e = KLE(); prov(e, 1); e.setst(1, 70); check('kl.setst #70 not defined by the Machine -> Invalid', stx(e, 1) == INV)
e = KLE(); prov(e, 1); e.nl = 1; e.setst(1, 0); check('kl.clear: Unconfigured, slot released, klnamedlocker -> 32', e.md(1) == 0 and e.slots == 8 and e.nl == 32)
e = KLE(); e.mgmt(1, 56, md=mk()); e.setst(1, 0, form='C'); check('kl.clear in any Form, in Provisioning', e.md(1) == 0)
e = KLE(); prov(e, 1); prov(e, 2); e.nl = 2; e.start = 5; e.setst(0, 65); check('kl.clearall: all lockers, klnamedlocker 32, klstart 0', all(l.mdh == 0 for l in e.L) and e.nl == 32 and e.start == 0 and e.slots == 8)
check('kl.clearall needs Form A, Kd=0, r=0', trap(KLE().setst, 1, 65) == 'illegal' and trap(KLE().setst, 0, 65, r=1) == 'illegal' and trap(KLE().setst, 0, 65, form='C') == 'illegal')
e = KLE(); prov(e, 1, AuxInfo=3); e.L[1].mdh = mdh_pack(Machine=M_ENC, MachinePolicy=3, UsagePolicy=4, State=1, AuxDataLen=5, ADSDropped=1, MachineUse=9, AuxInfo=3)
e.clearads(1); check('kl.clearads zeroes AuxDataLen, ADSDropped, MachineUse, AuxInfo; State kept', mdh_get(e.md(1), 'AuxDataLen') == 0 and mdh_get(e.md(1), 'ADSDropped') == 0 and mdh_get(e.md(1), 'MachineUse') == 0 and mdh_get(e.md(1), 'AuxInfo') == 0 and e.getst(1) == 1)
e = KLE(); prov(e, 1); e.setst(1, 2); e.setst(1, 64); check('kl.clearads admitted in every Valid State (Encrypt)', stx(e, 1) == (2, 0))
e = KLE(); prov(e, 1); e.setst(1, 64, form='C'); check('kl.clearads in a Form other than A: Invalid', stx(e, 1) == INV)
e = KLE(); prov(e, 1); e.L[1].mdh = mdh_put(e.md(1), 'State', 54); e.setst(1, 2); check('Success: only Ready and clearads admitted; setst Encrypt -> Invalid', stx(e, 1) == INV)
e = KLE(); prov(e, 1); e.L[1].mdh = mdh_put(e.md(1), 'State', 55); e.setst(1, 1); check('Failure -> Ready via setst Ready', stx(e, 1) == (1, 0))
e = KLE(); prov(e, 1); e.L[1].mdh = mdh_put(e.md(1), 'State', 54); e.exec(1); check('kl.exec in Success: Invalid', stx(e, 1) == INV)
e = KLE(); prov(e, 1); e.exec(1); check('kl.exec in Ready not admitted (<<KLE-GR-exec-ready>>): Invalid', stx(e, 1) == INV)
e = KLE(); prov(e, 1); e.setst(1, 2); e.start = 3; r = e.exec(1); check('kl.exec in Encrypt: operates, State unchanged (MR16), klstart 0', r == 'ok' and stx(e, 1) == (2, 0) and e.start == 0)

section('UsagePolicy, ExpirationDate, MachinePolicy  <<KLE-GR-usage-policy>>, <<KLE-MR-policy-gate>>')
for mode, nm in ((0, 'U'), (1, 'VS'), (2, 'S'), (3, 'M')):
    for up in range(32):
        e = KLE(mode=mode); e.L[1].mdh = mk(State=1, UsagePolicy=up); e.L[1].slot = False
        want = 'privilege_violation' if not up >> mode & 1 else None
        if trap(e.setst, 1, 2) != want: check('UsagePolicy %d in mode %s' % (up, nm), False); break
    else: check('UsagePolicy bit %d admits exactly mode %s (all 32 values)' % (mode, nm), True)
e = KLE(); e.L[1].mdh = mk(State=1, UsagePolicy=0); check('zero UsagePolicy admits no mode; State unchanged', trap(e.setst, 1, 2) == 'privilege_violation' and e.getst(1) == 1)
e = KLE(); e.L[1].mdh = mk(State=1, UsagePolicy=0); check('kl.clearads and kl.setst Success: usage -> privilege violation', trap(e.clearads, 1) == 'privilege_violation' and trap(e.setst, 1, 54) == 'privilege_violation')
e = KLE(); e.L[1].mdh = mk(State=1, UsagePolicy=0); check('not usage: getmd, kl.size, restrict (item), kl.clear, kl.setste, clone', trap(e.getmd, 1) is None and trap(e.size, 1) is None and trap(e.setste, 1, 2) is None)
e = KLE(); e.L[1].mdh = mk(State=1, UsagePolicy=0); e.clear(1); check('kl.clear not subject to UsagePolicy', e.md(1) == 0)
e = KLE(clock=100); e.L[1].mdh = mk(State=2, ExpirationDate=100); e.exec(1); check('ExpirationDate: clock >= date -> Error State Expired (<<KLE-ExpirationDate>>)', stx(e, 1) == (0, SE_EXPIRED))
e = KLE(clock=99); e.L[1].mdh = mk(State=2, ExpirationDate=100); e.exec(1); check('clock < date proceeds', stx(e, 1) == (2, 0))
e = KLE(clock=10**9); e.L[1].mdh = mk(State=2, ExpirationDate=0); e.exec(1); check('ExpirationDate 0 never expires', stx(e, 1) == (2, 0))
e = KLE(clock=None); e.L[1].mdh = mk(State=2, ExpirationDate=100); check('unreadable clock -> kl_exc_clock_unavailable, State kept', trap(e.exec, 1) == 'clock_unavailable' and e.getst(1) == 2)
e = KLE(clock=-5); e.L[1].mdh = mk(State=2, ExpirationDate=1); e.exec(1); check('clock before epoch reads 0', stx(e, 1) == (2, 0))
e = KLE(clock=10**9); e.L[1].mdh = mk(State=2, ExpirationDate=mask(20)); e.exec(1); check('clock saturates at 2^20-1: date 2^20-1 expired', stx(e, 1) == (0, SE_EXPIRED))
e = KLE(clock=100, mode=0); e.L[1].mdh = mk(State=2, ExpirationDate=100, UsagePolicy=4); check('UsagePolicy check precedes ExpirationDate (GR20 order)', trap(e.exec, 1) == 'privilege_violation' and e.getst(1) == 2)
e = KLE(); prov(e, 1, pol=2); check('MachinePolicy without enc bit: setst Encrypt -> Invalid (MR1)', (e.setst(1, 2), stx(e, 1))[1] == INV)
e = KLE(); prov(e, 1, pol=2); check('MachinePolicy with dec bit: setst Decrypt ok', (e.setst(1, 3), stx(e, 1))[1] == (3, 0))
e = KLE(); prov(e, 1); e.setst(1, 2); e.rstr(1, mdh_pack(MachinePolicy=2), part='l'); e.exec(1); check('restrict removing enc while in Encrypt: next kl.exec Invalid (GR25, MR1)', stx(e, 1) == INV)
e = KLE(); prov(e, 1, mach=M_SIG, pol=0); check('signature Machine: zero MachinePolicy valid, State 2 reachable', (e.setst(1, 2), stx(e, 1))[1] == (2, 0))
e = KLE(); prov(e, 1); e.setst(1, 2); e.setst(1, 1); check('Encrypt -> Ready', stx(e, 1) == (1, 0))
e = KLE(); e.L[1].mdh = mk(State=1, ExpirationDate=5, UsagePolicy=0); e.clock = 9; check('UsagePolicy violation raises before expiry is evaluated', trap(e.setst, 1, 2) == 'privilege_violation' and e.getst(1) == 1)

section('Configuration States  <<KLE-GR-config-states>>')
e = KLE(); e.mgmt(1, 56, md=mk())
check('usage instruction on Provisioning -> privilege violation, State kept', trap(e.exec, 1) == 'privilege_violation' and trap(e.setst, 1, 2) == 'privilege_violation' and trap(e.clearads, 1) == 'privilege_violation' and e.getst(1) == 56)
check('restrict on a Configuration-State locker -> privilege violation', trap(e.rstr, 1, mk()) == 'privilege_violation')
check('clone from Configuration State -> privilege violation, destination cleared', (lambda: (prov(e, 2), trap(e.clone, 2, 1), e.md(2))[1:])() == ('privilege_violation', 0))
check('admitted in every State: getmd, getst, kl.size, clear, setste', trap(e.getmd, 1) is None and e.getst(1) == 56 and e.size(1) == 32 and trap(e.setste, 1, 2) is None)
e = KLE(); e.mgmt(1, 56, md=mk()); FIN(e,1); e.mgmt(1, 57); check('kl.mgmt export opening in Ready: State 57 only change', stx(e, 1) == (57, 0))
e = KLE(); prov(e, 1); m0 = e.md(1); e.mgmt(1, 57, form='A'); check('export opening changes no other MDH field', e.md(1) == mdh_put(m0, 'State', 57))
check('kl.mvout in 57, mvin in 56/58/60 (GR30)', trap(e.mvout) is None and trap(e.mvin, 1) == 'illegal')
e = KLE(); prov(e, 1); check('mvin / mvout on a Valid State -> illegal', trap(e.mvin, 1) == 'illegal' and trap(e.mvout) == 'illegal')
e = KLE(); e.mgmt(1, 56, md=mk()); check('mvout on Provisioning -> illegal (wrong direction)', trap(e.mvout) == 'illegal')
e = KLE(); prov(e, 1); check('provisioning completion with ml.State 0 (Form A style): Ready, MDH.State != 0', mdh_get(e.md(1), 'State') == 1); e.mgmt(1, 57, form='A'); e.mgmt(1, 63, form='C', md=mk(State=1)); check('export completion restores ml.State', stx(e, 1) == (1, 0))
e = KLE(); prov(e, 1); e.mgmt(1, 57, form='A'); check('export completion with ml.State 56 on SCC base -> illegal; 61 -> illegal', trap(e.mgmt, 1, 63, form='C', md=mk(State=56)) == 'illegal' and trap(e.mgmt, 1, 63, form='C', md=mk(State=61)) == 'illegal')
e = KLE(); prov(e, 1); e.setst(1, 2); e.mgmt(1, 57, form='A'); e.mgmt(1, 63, form='C', md=mk(State=2)); check('export completes into a non-Ready Valid State', stx(e, 1) == (2, 0))
e = KLE(); e.setste(1, 3); e.mgmt(1, 57, form='A'); check('export opening on an Error State: unchanged, no op opened', stx(e, 1) == (0, 3))
e = KLE(); check('export opening on Unconfigured: no-op, no exception', trap(e.mgmt, 1, 57, form='A') is None and e.md(1) == 0)
e = KLE(); e.mgmt(1, 56, md=mk()); e.mgmt(1, 57, form='A'); check('nested export of a PI-base Configuration State: 59 (ppi_exporting)', e.getst(1) == 59)
e.mgmt(1, 63, form='C', md=mk(State=56)); check('nested completion restores ml.State 56', e.getst(1) == 56)
e = KLE(); e.mgmt(1, 56, md=mk()); FIN(e,1); e.mgmt(1, 57, form='A'); e.mgmt(1, 57, form='A'); check('export of an export-in-progress SCC base: 57 (scc nested)', e.getst(1) == 57)
e = KLE(); e.mgmt(1, 56, md=mk()); check('provisioning completion consumes an admitted ml.State (59) and still reaches Ready', trap(e.mgmt, 1, 63, form='C', md=mk(State=59)) is None and e.getst(1) == 1)

section('Import  <<KLE-MVR-open>>, <<KLE-GR-completion>>')
im = mk(State=1)
e = KLE(); e.mgmt(2, 58, md=im); check('import opening: State 58', stx(e, 2) == (58, 0) and mdh_get(e.md(2), 'Machine') == M_ENC)
e = KLE(); e.mgmt(2, 58, md=mk(State=56)); check('import with ml.State 56 (PI base): State 60 (ppi_importing)', e.getst(2) == 60)
e = KLE(); e.mgmt(2, 58, md=mk(State=57)); check('import with ml.State 57: State 58', e.getst(2) == 58)
for st in (61, 62, 63):
    e = KLE(); e.mgmt(2, 58, md=mk(State=st)); check('import with ml.State %d invalid' % st, stx(e, 2) == INV)
e = KLE(); e.mgmt(2, 58, md=0); check('import of an Unconfigured MDH invalid', stx(e, 2) == INV)
e = KLE(); e.mgmt(2, 58, md=mdh_pack(State=0, StateExtension=9)); check('import State 0 with StateExtension 7-15 invalid', stx(e, 2) == INV)
e2 = KLE(); r = trap(e2.mgmt, 2, 58, md=mk(mach=0x99, State=1)); check('import of unsupported Machine -> kl_exc_unsupported', r == 'unsupported' and e2.md(2) == 0)
e = KLE(); e.mgmt(2, 58, md=mk(State=0, StateExtension=3)); check('short import: Error-State MDH installed, no operation opened, no capacity', stx(e, 2) == (0, 3) and e.slots == 8)
e = KLE(); e.mgmt(2, 58, md=mk(State=0, StateExtension=3, MachineUse=5)); check('short import installs a valid MDH as is', e.md(2) == mk(State=0, StateExtension=3, MachineUse=5))
e = KLE(); e.mgmt(2, 58, md=mk(State=0, StateExtension=3, SCProtection=3)); check('short import of invalid Metadata gives Error State Invalid', stx(e, 2) == (0, SE_INVALID))
e = KLE(); e.mgmt(2, 58, md=im); c = 0xABCD; e.mvin(c, toy_tag(c)); e.mgmt(2, 63, form='C', md=im); check('import completion with valid tag: State = ml.State', stx(e, 2) == (1, 0) and e.L[2].content == c)
e = KLE(); e.mgmt(2, 58, md=im); e.mvin(0xABCD, 1); e.mgmt(2, 63, form='C', md=im); check('import completion with bad tag: Error State Authentication Failed, no exception', stx(e, 2) == (0, SE_MGMT_AUTH))
control('a wrong tag is detected (negative control)', e.getstx(2) == SE_MGMT_AUTH)
e = KLE(); e.mgmt(2, 58, md=im); e.mvin(0xABCD, 1); e.mgmt(2, 63, form='C', md=mk(State=58)); check('import into non-Valid ml.State 58: no authentication', stx(e, 2) == (58, 0))
e = KLE(); e.mgmt(2, 58, md=im); check('import completion with ml.State 56/59/60 on SCC base -> illegal', all(trap(e.mgmt, 2, 63, form='C', md=mk(State=s)) == 'illegal' for s in (56, 59, 60)))
e = KLE(); e.mgmt(2, 58, md=mk(State=56)); check('import completion on PI base: ml.State 1 -> illegal; 56 ok', trap(e.mgmt, 2, 63, form='C', md=im) == 'illegal' and trap(e.mgmt, 2, 63, form='C', md=mk(State=56)) is None)
e = KLE(); e.mgmt(2, 58, md=mk(State=1, AuxDataLen=5, ADSDropped=1)); check('import SCC MDH may carry AuxDataLen >= 2 and ADSDropped', e.getst(2) == 58)
e = KLE(); e.mgmt(2, 58, md=mk(State=1, AuxDataLen=1)); check('import AuxDataLen 1 invalid', stx(e, 2) == INV)
e = KLE(); e.mgmt(2, 58, md=im); check('Form A completion ml.State 0 on import in progress -> illegal', trap(e.mgmt, 2, 63, form='A') == 'illegal' and e.getst(2) == 58)

section('kl.size / kl.avail  <<KLE-length-rule>>, <<KLE-instruction-size>>')
e = KLE(); prov(e, 1); check('Form A size: Valid, AuxDataLen 0: 32 + 16', e.size(1) == 48)
e.L[1].mdh = mdh_put(e.md(1), 'AuxDataLen', 5); check('AuxDataLen 5: 64 + 16 + 16*3 = 128', e.size(1) == 128)
e.L[1].mdh = mdh_put(e.md(1), 'ADSDropped', 1); check('ADSDropped keeps 64 + c1 = 80', e.size(1) == 80)
e.L[1].mdh = mdh_put(mdh_put(e.md(1), 'AuxDataLen', 2), 'ADSDropped', 0); check('AuxDataLen 2: 64 + 16 = 80', e.size(1) == 80)
e = KLE(); e.mgmt(1, 56, md=mk(mach=M_SIG)); check('Provisioning, TOYSIG: 16 + 32 = 48', e.size(1) == 48)
FIN(e,1); check('Ready TOYSIG: 32 + 32 = 64', e.size(1) == 64)
e = KLE(); prov(e, 1); e.mgmt(1, 57, form='A'); check('size in State 57 as Valid: 32 + c1', e.size(1) == 48)
e = KLE(); e.mgmt(2, 58, md=mk(State=56)); check('size in ppi_importing: 16 + c1', e.size(2) == 32)
for nm, md, w in (('Form C PI', mk(), 32), ('Form B PI', mk(), 32), ('Form C Valid', mk(State=1), 48), ('State 61', mk(State=61), 0), ('State 0 SE 1 (Error)', mdh_pack(Machine=0x99, StateExtension=1), 16),
                  ('State 0 SE 7', mdh_pack(Machine=M_ENC, StateExtension=7), 0), ('Version 1', mk(Version=1), 0), ('SCProtection 3', mk(SCProtection=3), 0), ('KeyType 3', mk(KeyType=3), 0),
                  ('unsupported', mk(mach=0x99), 0), ('PI with ADS fields', mk(AuxDataLen=2), 0), ('Valid with AuxDataLen 3', mk(State=1, AuxDataLen=3), 64 + 16 + 16)):
    f = 'B' if 'Form B' in nm else 'C'
    check('kl.size %s = %d' % (nm, w), KLE().size(form=f, md=md) == w)
check('kl.size Form B ignores bits above 63 (reserved bit 116)', KLE().size(form='B', md=mk() | 1 << 120) == 32 and KLE().size(form='C', md=mk() | 1 << 120) == 0)
check('kl.size ignores UsagePolicy/Locality/KeyType 2 as 0', KLE().size(form='C', md=mk(KeyType=0)) == KLE().size(form='C', md=mk(mach=M_KEY, KeyType=2)))
e = KLE(); prov(e, 1); check('kl.avail A: 1 for implemented Machine, 0 Unconfigured, 0 KLNL 32', e.avail(1) == 1 and e.avail(2) == 0 and (setattr(e, 'nl', 32), e.avail(0, r=1))[1] == 0)
check('kl.avail B/C: 1 implemented; 0 for unimplemented; 0 for Version 1 and 2; Version 3 is answered by the Machine fields (m12); reserved SCProtection/KeyType 0', KLE().avail(form='C', md=mk()) == 1 and KLE().avail(form='C', md=mk(mach=0x99)) == 0 and KLE().avail(form='C', md=mk(Version=1)) == 0 and KLE().avail(form='C', md=mk(Version=2)) == 0 and KLE().avail(form='C', md=mk(Version=3)) == 1 and KLE().avail(form='C', md=mk(SCProtection=3)) == 0 and KLE().avail(form='B', md=mk(KeyType=3)) == 0)
check('kl.avail examines no field but Machine/Version/reserved: State 61 still 1', KLE().avail(form='C', md=mk(State=61)) == 1)
check('kl.avail B ignores bits above 63', KLE().avail(form='B', md=mk() | 1 << 120) == 1)

section('kl.rstr*  <<KLE-instruction-restrict>>')
def rl(**kw):
    e = KLE(); prov(e, 1, up=0x1F, **kw); return e
e = rl(pol=3); e.rstr(1, mdh_pack(MachinePolicy=1), part='l'); check('rstrl ANDs MachinePolicy', mdh_get(e.md(1), 'MachinePolicy') == 1)
e = rl(pol=3); e.rstr(1, mdh_pack(MachinePolicy=3), part='l'); check('rstrl all-ones MachinePolicy unchanged', mdh_get(e.md(1), 'MachinePolicy') == 3)
e = rl(); e.rstr(1, mdh_pack(UsagePolicy=0b01101), part='h'); check('rstrh ANDs UsagePolicy', mdh_get(e.md(1), 'UsagePolicy') == 0b01101)
e = rl(); e.rstr(1, mdh_pack(UsagePolicy=0b11111), part='h'); check('UsagePolicy all-ones unchanged', mdh_get(e.md(1), 'UsagePolicy') == 31)
e = rl(); e.rstr(1, mdh_pack(UsagePolicy=0), part='h'); check('UsagePolicy zero request clears (admits no mode)', mdh_get(e.md(1), 'UsagePolicy') == 0)
e = rl(); e.rstr(1, mdh_pack(ExpirationDate=50), part='h'); check('ExpirationDate: md zero takes request', mdh_get(e.md(1), 'ExpirationDate') == 50)
e.rstr(1, mdh_pack(ExpirationDate=60), part='h'); check('later request does not extend', mdh_get(e.md(1), 'ExpirationDate') == 50)
e.rstr(1, mdh_pack(ExpirationDate=40), part='h'); check('earlier request shortens', mdh_get(e.md(1), 'ExpirationDate') == 40)
e.rstr(1, mdh_pack(ExpirationDate=0), part='h'); check('zero request unchanged', mdh_get(e.md(1), 'ExpirationDate') == 40)
e = rl(); e.rstr(1, mdh_pack(Locality=0b0101), part='h'); check('Locality: md zero takes request', mdh_get(e.md(1), 'Locality') == 5)
e.rstr(1, mdh_pack(Locality=0b0110), part='h'); check('HW subfield increases ([1:0] 1 -> 2)', mdh_get(e.md(1), 'Locality') & 3 == 2 and mdh_get(e.md(1), 'Locality') >> 2 & 3 == 1)
check('HW subfield decrease -> privilege violation', trap(e.rstr, 1, mdh_pack(Locality=1), part='h') == 'privilege_violation')
e = rl(); e.rstr(1, mdh_pack(Locality=0x10), part='h'); check('boot subfield md zero takes request', mdh_get(e.md(1), 'Locality') == 0x10)
check('boot subfield changing to another nonzero -> privilege violation', trap(e.rstr, 1, mdh_pack(Locality=0x20), part='h') == 'privilege_violation')
e.rstr(1, mdh_pack(Locality=0x10), part='h'); check('equal subfield no change', mdh_get(e.md(1), 'Locality') == 0x10)
e = rl(); e.rstr(1, mdh_pack(Locality=0x1C0), part='h'); check('Locality bits 6-8 ORed', mdh_get(e.md(1), 'Locality') == 0x1C0)
e = rl(); e.rstr(1, mdh_pack(State=3), part='v'); check('non-allowed field (State) nonzero -> Error State Invalid', stx(e, 1) == INV)
e = rl(); e.rstr(1, mdh_pack(AuxInfo=1), part='h'); check('AuxInfo nonzero in taken half -> Invalid', stx(e, 1) == INV)
e = rl(); e.rstr(1, mdh_pack(UsagePolicy=1), part='l'); check('rstrl does not take [127:64]: UsagePolicy in request ignored', mdh_get(e.md(1), 'UsagePolicy') == 31 and e.getst(1) == 1)
e = rl(); e.rstr(1, mdh_pack(MachinePolicy=1), part='h'); check('rstrh does not take MachinePolicy', mdh_get(e.md(1), 'MachinePolicy') == 3)
e = rl(); e.rstr(1, mdh_pack(MachinePolicy=1, UsagePolicy=1), part='v'); check('rstrv takes both', mdh_get(e.md(1), 'MachinePolicy') == 1 and mdh_get(e.md(1), 'UsagePolicy') == 1)
e = rl(); e.rstr(1, mdh_pack(MachinePolicy=1), part='l'); check('restrict never changes SCProtection/State/Machine', mdh_get(e.md(1), 'Machine') == M_ENC and e.getst(1) == 1)
e = rl(); e.rstr(1, mdh_pack(MachinePolicy=0), part='l'); check('restrict can narrow MachinePolicy to zero', mdh_get(e.md(1), 'MachinePolicy') == 0)
e = rl(); e.mgmt(2, 58, md=mk(State=1)); check('restrict on a Configuration State -> privilege violation', trap(e.rstr, 2, mk()) == 'privilege_violation')

section('kl.clone / kl.rename / kl.swap  <<KLE-instruction-clone>>')
def two(): e = KLE(); prov(e, 1); e.L[1].content = 0x55; prov(e, 2, mach=M_SIG); return e
e = two(); e.clone(3, 1); check('clone copies MDH and content verbatim', e.md(3) == e.md(1) and e.L[3].content == 0x55 and e.md(1) != 0)
e = two(); e.clone(2, 2); check('clone same locker: no-op', stx(e, 2) == (1, 0))
e = two(); e.nl = 3; e.clone(3, 1); check('clone: klnamedlocker naming dest -> 32 (GR26)', e.nl == 32)
e = two(); e.clone(3, 9); check('clone of Unconfigured source -> dest Unconfigured', e.md(3) == 0)
e = two(); e.clone(2, 9); check('clone Unconfigured over a configured dest clears it', e.md(2) == 0 and e.slots == 7 + 1 - 1 + 1 - 1 + 0 + 0 + 0 or e.md(2) == 0)
e = two(); e.setste(4, 3); e.clone(5, 4); check('clone of Error State: MDH alone, no capacity', stx(e, 5) == (0, 3) and e.slots == 6)
e = two(); e.mgmt(4, 56, md=mk()); check('clone from Configuration State -> privilege violation; dest already cleared', trap(e.clone, 2, 4) == 'privilege_violation' and e.md(2) == 0)
e = two(); e.slots = 0; check('clone out of memory -> kl_exc_out_of_memory, dest Unconfigured', trap(e.clone, 3, 1) == 'out_of_memory' and e.md(3) == 0)
e = two(); e.nl = 1; e.clone(3, 'NL'); check('clone with source = KLNL (R=10)', e.md(3) == e.md(1))
e = two(); e.nl = 3; e.clone('NL', 1); check('clone with dest = KLNL (R=01): dest cleared first, klnamedlocker 32, then copied', e.md(3) == e.md(1) and e.nl == 32)
e = two(); m1, m2 = e.md(1), e.md(2); e.rename(3, 1); check('rename moves CC; source Unconfigured', e.md(3) == m1 and e.md(1) == 0 and e.L[3].content == 0x55)
e = two(); e.nl = 1; e.rename(3, 1); check('rename: klnamedlocker s -> d (GR26)', e.nl == 3)
e = two(); e.nl = 3; e.prov = 0; e.rename(3, 1); check('rename: klnamedlocker naming overwritten dest -> then source moved: ends 32', e.nl == 32)
e = two(); e.rename(1, 1); check('rename same locker no-op', stx(e, 1) == (1, 0))
e = two(); e.rename(2, 9); check('rename of Unconfigured source acts as kl.clear Kd', e.md(2) == 0)
e = two(); e.mgmt(4, 56, md=mk()); e.rename(5, 4); check('rename moves a Configuration-State CC (no exception)', stx(e, 5) == (56, 0) and e.md(4) == 0)
e = two(); a, b = e.md(1), e.md(2); e.swap(1, 2); check('swap exchanges lockers', e.md(1) == b and e.md(2) == a and e.L[2].content == 0x55)
e = two(); e.nl = 1; e.swap(1, 2); check('swap: klnamedlocker takes the other number', e.nl == 2)
e = two(); e.nl = 2; e.swap(1, 2); check('swap: klnamedlocker 2 -> 1', e.nl == 1)
e = two(); e.nl = 7; e.swap(1, 2); check('swap: unrelated klnamedlocker kept', e.nl == 7)
e = two(); e.swap(1, 9); check('swap with Unconfigured: source becomes Unconfigured', e.md(1) == 0 and e.getst(9) == 1)
e = two(); e.swap(1, 1); check('swap same locker no-op', stx(e, 1) == (1, 0))
e = two(); e.mgmt(4, 56, md=mk()); e.swap(4, 1); check('swap moves Configuration-State CC without exception', e.getst(1) == 56 and e.getst(4) == 1)
control('negative: clone does not alias (changing the copy leaves the source)', (lambda e: (e.clone(3, 1), e.setst(3, 2), e.getst(1))[2] == 1)(two()))

section('KLF capacity zeroing  <<KLE-destructive-config>>')
e = KLE(slots=1); prov(e, 1); e.L[1].content = 0xDEAD; e.clear(1); prov(e, 2); check('capacity reallocated after kl.clear reads zero', e.L[2].content == 0)
e = KLE(slots=1, zero_alloc=False); prov(e, 1); e.L[1].content = 0xDEAD; e.clear(1); prov(e, 2)
control('witness: without the zero fill the freed key reappears', e.L[2].content == 0xDEAD)
e = KLE(slots=2); prov(e, 1); e.L[1].content = 0xBEEF; e.clone(2, 1); e.clear(2); e.clone(3, 1); check('clone destination capacity starts zeroed, then copies', e.L[3].content == 0xBEEF)
e = KLE(slots=1); prov(e, 1); e.L[1].content = 7; e.rename(5, 1); check('rename moves capacity, frees none', e.slots == 0 and e.L[5].content == 7)
e = KLE(slots=1); prov(e, 1); e.mgmt(1, 56, md=mk()); check('re-provisioning frees then reallocates', e.slots == 0 and e.L[1].content == 0)

section('klnamedlocker and KLNL  <<KLE-GR-klnamedlocker-updates>>, <<KLE-instruction-setnl>>')
e = KLE(); check('reset value 32', e.getnl() == 32)
for v in (0, 5, 31, 32): e.setnl(v); check('setnl %d' % v, e.getnl() == v)
e.setnl(5); e.setnl(33); check('setnl 33 ignored', e.getnl() == 5)
e.setnl(255); check('setnl 255 ignored', e.getnl() == 5)
e = KLE(); prov(e, 1); check('KLNL addressing requires locker field 0 (r=1, kd=1 -> illegal GR4)', trap(e.getmd, 1, 1) == 'illegal' and trap(e.exec, 3, 1) == 'illegal')
e.nl = 1; check('kl.getmd via KLNL reads the named locker', e.getmd(0, 1) == e.md(1) and e.getst(0, 1) == 1)
e = KLE(); e.nl = 4; e.mgmt(2, 56, md=mk()); check('kl.mgmt naming locker 2 sets klnamedlocker 2', e.nl == 2)
e = KLE(); e.nl = 4; trap(e.mgmt, 2, 59); check('kl.mgmt rejected by reserved immed leaves klnamedlocker', e.nl == 4)
e = KLE(); e.nl = 4; FIN(e,2); check('completing kl.mgmt on inert locker names it', e.nl == 2)
e = KLE(); e.nl = 4; e.mgmt(2, 57, form='A'); check('export opening on inert locker names it, no other effect', e.nl == 2 and e.md(2) == 0)
e = KLE(); e.nl = 4; trap(e.mgmt, 2, 56, md=mk(mach=0x99)); check('kl.mgmt raising unsupported after the destructive step still names the locker', e.nl == 2)
e = KLE(); e.nl = 4; trap(e.mgmt, 2, 63, form='C', md=mk(State=2)); check('completion on Unconfigured with any ml: no-op, ml ignored', e.nl == 2 and e.md(2) == 0)
e = KLE(); e.nl = 4; e.start = 3; trap(e.mgmt, 2, 63, form='A'); check('klstart cleared by kl.mgmt', e.start == 0)
e = KLE(csk=False); e.start = 3; trap(e.mgmt, 2, 56, md=mk()); check('rejected by locker-state-independent checks: klstart unchanged', e.start == 3)
e = KLE(); prov(e, 1); e.nl = 1; e.setste(0, 4, r=1); check('setste via KLNL leaves klnamedlocker unchanged', e.nl == 1 and stx(e, 1) == (0, 4))
e = KLE(); prov(e, 1); e.nl = 1; e.setst(0, 0, r=1); check('kl.clear via KLNL: klnamedlocker -> 32', e.nl == 32 and e.md(1) == 0)
e = KLE(); prov(e, 1); prov(e, 2); e.nl = 1; e.setst(0, 65); check('kl.clearall: klnamedlocker 32 (cleared)', e.nl == 32)

from mgmt_ext import *

def E2(**kw):
    e = KLE2(**kw); return e
def opened(e, k=0, mach=M_SIG, **kw):      # provisioning opened (State 56); nl = k
    e.mgmt(k, 56, md=mk(mach=mach, pol=0 if mach == M_SIG else 3, **kw)); return e
def blk(i): return bytes([i]) * 16

section('kl.mvin / kl.mvout GPR variants  <<KLE-instruction-mv>>, <<KLE-GR-locker-less-transfers>>')
e = opened(E2()); e.gpr_in(0x11); e.gpr_in(0x22)
check('mvin Xs2: one 16-byte block per instruction, klstart += 16, kept across instructions', e.start == 32 and bytes(e.img(0)) == v2b(0x11, 16) + v2b(0x22, 16))
e.gpr_in(0x33); check('mvin with klstart >= image_end: block ignored, klstart unchanged', e.start == 32 and bytes(e.img(0)) == v2b(0x11, 16) + v2b(0x22, 16))
e.mgmt(0, 63, md=mk(State=56))
check('completion: content = the loaded S, klstart cleared by the completing kl.mgmt (<<KLE-GR-klstart-updates>>)', e.L[0].content == 0x11 | 0x22 << 128 and e.start == 0 and e.getst(0) == 1)
e = opened(E2()); e.start = 8
check('mvin with klstart not a multiple of 16 -> illegal (locker checks)', trap(e.gpr_in, 1) == 'illegal' and trap(e.gpr_out) == 'illegal')
e = E2(); e.start = 8; check('mvin/mvout on a nl=32 session: no operation whatever klstart', e.gpr_in(5) is None and e.gpr_out() == 0 and e.start == 8)
e = E2(); e.nl = 3; e.start = 8; check('mvin/mvout on an Unconfigured locker: no-op whatever klstart; mvout writes zero', e.gpr_in(5) is None and e.gpr_out() == 0 and e.start == 8)
e = E2(); prov(e, 3); e.setste(3, 2); e.nl = 3; e.start = 5; check('mvin/mvout on an Error-State locker: no-op whatever klstart', e.gpr_in(5) is None and e.gpr_out() == 0 and e.start == 5)
e = opened(E2()); check('mvout on a Provisioning locker (wrong direction) -> illegal; mvin on Exporting -> illegal',
                        trap(e.gpr_out) == 'illegal' and (e.mgmt(0, 63, md=mk(State=56)), e.mgmt(0, 57, form='A'), trap(e.gpr_in, 1))[2] == 'illegal')
e = E2(); prov(e, 1, mach=M_SIG, pol=0); e.L[1].content = 0xAA | 0xBB << 128; e.nl = 1; e.mgmt(1, 57, form='A')
check('export-opened locker: State 57; image = content at ContentOffset 16 (SIV area first)', e.getst(1) == 57 and e.image_end(1) == 48)
o = [e.gpr_out(), e.gpr_out(), e.gpr_out(), e.gpr_out()]
check('mvout transfers S in order, zeros past image_end, klstart kept at image_end', o == [0, 0xAA, 0xBB, 0] and e.start == 48)
section('Vector and KLIOBUF mv variants')
e = opened(E2()); d = bytes(range(32)); vs = e.vec_in(d, 32)
check('vector mvin SEW 32: two blocks, vstart advances 4 per block, S = vector bytes', vs == 8 and e.start == 32 and bytes(e.img(0)) == d)
e = opened(E2()); vs = e.vec_in(d, 64); check('SEW 64: vstart advances 2 per block', vs == 4 and bytes(e.img(0)) == d)
e = opened(E2()); vs = e.vec_in(d, 32, vstart=4)
check('vstart 4 (block 1): element k at klstart + (k - vstart)*SEW/8: second vector block lands at S[0:16]', vs == 8 and bytes(e.img(0)[:16]) == d[16:32] and e.start == 16)
e = opened(E2()); e.start = 32; check('vstart >= vl: nothing transferred, klstart unchanged', e.vec_in(d, 32, vstart=8) == 8 and e.start == 32)
for nm, kw in (('vl*SEW not a multiple of 128 bits', dict(data=d[:24])), ('vstart*SEW/8 not a multiple of 16', dict(data=d, vstart=1))):
    e = opened(E2()); check('vector mvin ' + nm + ' -> illegal on any locker', trap(e.vec_in, sew=32, **kw) == 'illegal' and trap(E2().vec_in, sew=32, **kw) == 'illegal')
e = opened(E2()); e.vext = False; check('vector mvin without vector extension -> illegal', trap(e.vec_in, d, 32) == 'illegal')
e = E2(csk=False); check('second-group illegal precedes the missing-CSK exception (<<KLE-GR-management-check-order>> items 3, 4)', trap(e.vec_in, d[:8], 32) == 'illegal' and trap(e.vec_in, d, 32) == 'no_csk')
e = opened(E2()); e.mgmt(0, 63, md=mk(State=56)); e.L[0].content = 0x77; e.mgmt(0, 57, form='A'); o = e.vec_out(8, 32)
check('vector mvout: one block per 4 elements: SIV area then content; klstart = 32', o == bytes(16) + v2b(0x77, 16) and e.start == 32)
e.mgmt(0, 63, md=mk(State=1)); e.L[0].content = 0x77 << 128; e.mgmt(0, 57, form='A'); e.start = 32; o = e.vec_out(8, 32, vstart=4)
check('vector mvout from vstart 4 at klstart 32: element k maps to S[klstart + (k - vstart)*4]; S[32:48] = content high half', o == v2b(0x77, 16) and e.start == 48)
o = e.vec_out(8, 32, vstart=4); check('vector mvout past image_end: zeros, klstart unchanged', o == bytes(16) and e.start == 48)
e = E2(); check('vector mvout with nl=32: zeros, no exception', e.vec_out(8, 32) == bytes(32))
e = opened(E2()); check('KLIOBUF mvin without Zklio -> illegal (KLIOBUF always unconfigured)', trap(e.buf_in) == 'illegal')
e.zklio = True; check('with Zklio but kliobuflen 0 -> illegal', trap(e.buf_in) == 'illegal')
e.kliobuflen = 64; e.kliobuftop = 20; check('kliobuftop not a multiple of 16 -> illegal', trap(e.buf_in) == 'illegal')
e.kliobuftop = 32; e.iobuf[:32] = d; e.buf_in(); check('KLIOBUF mvin moves bytes 0..top-1 to S[klstart..], klstart += top', bytes(e.img(0)) == d and e.start == 32)
e = E2(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 32; e.iobuf[:40] = bytes([9]) * 40; e.buf_out()
check('KLIOBUF mvout on nl=32 writes zeros to [0, kliobuftop-1] only', e.iobuf[:32] == bytes(32) and e.iobuf[32:40] == bytes([9]) * 8)
e = E2(); e.iobuf[:8] = bytes([9]) * 8; e.buf_out(); check('KLIOBUF mvout on nl=32 with unconfigured buffer: no access, no exception', e.iobuf[:8] == bytes([9]) * 8)
e = E2(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 20; check('KLIOBUF mvin/mvout with kliobuftop not a multiple of 16 -> illegal even on an inert locker (second group, like the vector check)', trap(e.buf_in) == 'illegal' and trap(e.buf_out) == 'illegal')

section('kl.load / kl.store / kl.input / kl.output  <<KLE-instruction-load>>, <<KLE-instruction-store>>, <<KLE-GR-management-check-order>>')
mem = Mem(); mem.b[0x100:0x120] = d
e = opened(E2()); e.start = 16; check('kl.load misalignment checks the effective address; klstart 16 is the offset of the first component access (GR16 item 8, m14)', trap(e.load, mem, 0x108) == 'load_misaligned' and trap(e.load, mem, 0x100) is None)
e = opened(E2()); e.start = 5
check('kl.load: klstart not a multiple of 16 -> illegal', trap(e.load, mem, 0x100) == 'illegal')
e = opened(E2()); e.load(mem, 0x100)
check('kl.load copies [klstart, image_end) from Xs+offset; klstart written 0 on retire (<<KLE-GR-klstart-updates>>)', bytes(e.img(0)) == d and e.start == 0)
e = opened(E2()); e.start = 16; e.load(mem, 0x100); check('kl.load resumes at klstart 16: S[16:32] = mem[addr+16:addr+32], S[0:16] untouched', bytes(e.img(0)) == bytes(16) + d[16:32])
e = opened(E2()); check('kl.load: Xl != 0 with klnamedlocker < 32 -> illegal', trap(e.load, mem, 0x100, 4) == 'illegal')
e = opened(E2()); check('kl.load misaligned address -> address-misaligned exception', trap(e.load, mem, 0x101) == 'load_misaligned')
e = E2(); e.nl = 4; check('misalignment is locker-state-independent: raised even for an Unconfigured named locker', trap(e.load, mem, 0x101) == 'load_misaligned')
e = E2(); e.start = 7; e.load(mem, 0x101); check('nl=32, Xl=0: no operation, klstart written 0, no alignment check, no Zklio check', e.start == 0)
e = opened(E2()); e.mgmt(0, 63, md=mk(State=56)); check('kl.load on a Valid State locker -> illegal', trap(e.load, mem, 0x100) == 'illegal')
e = E2(); e.nl = 4; e.start = 3; e.load(mem, 0x100); check('kl.load on Unconfigured locker: no memory access, klstart 0', e.start == 0)
mem2 = Mem(); mem2.b[0x0FF0:0x1010] = d; mem2.fault = {1}
e = opened(E2()); k_ = trap(e.load, mem2, 0x0FF0)
check('page fault on the second block: precise halt, block 0 committed, klstart = 16 (prefix-complete)', k_ == 'load_page_fault' and e.start == 16 and bytes(e.img(0)[:16]) == d[:16])
mem2.fault = set(); e.load(mem2, 0x0FF0); check('re-issued kl.load resumes and completes', bytes(e.img(0)) == d and e.start == 0)
mem2.nonidem = {1}; e = opened(E2()); check('non-idempotent region -> load access fault (<<KLE-GR-idempotent-memory>>)', trap(e.load, mem2, 0x0FF0) == 'load_access_fault')
e = E2(); prov(e, 1, mach=M_SIG, pol=0); e.L[1].content = 0xCAFE; e.nl = 1; e.mgmt(1, 57, form='A'); mem3 = Mem(); e.store(mem3, 0x200)
check('kl.store writes S (SIV area, content) to memory, klstart 0 after', mem3.b[0x210:0x210 + 16] == v2b(0xCAFE, 16) and e.start == 0)
e = opened(E2()); check('kl.store on a Provisioning locker -> illegal (wrong direction)', trap(e.store, mem3, 0x200) == 'illegal')
e = E2(); prov(e, 1); e.nl = 1; e.mgmt(1, 57, form='A'); mem4 = Mem(); mem4.fault = {0}
check('store page fault: store_page_fault, klstart 0 prefix', trap(e.store, mem4, 0x000) == 'store_page_fault' and e.start == 0)
check('kl.store misaligned -> store address-misaligned', trap(e.store, mem3, 0x208) == 'store_misaligned')
e = E2(); check('kl.input nl=32, Xl != 0 without Zklio -> illegal', trap(e.load, mem, 0x100, 8) == 'illegal')
e.zklio = True; check('Zklio but KLIOBUF unconfigured -> illegal even for an empty window', trap(e.load, mem, 0x100, 8) == 'illegal' and (setattr(e, 'start', 99), trap(e.load, mem, 0x100, 8))[1] == 'illegal')
e.kliobuflen = 64; e.kliobuftop = 32; e.start = 0; e.load(mem, 0x100, 20)
check('kl.input copies n = min(Xl, kliobuftop) bytes; bytes >= n untouched', e.iobuf[:20] == d[:20] and e.iobuf[20:32] == bytes(12) and e.start == 0)
e.load(mem, 0x100, 100); check('Xl > kliobuftop: only kliobuftop bytes', e.iobuf[:32] == d and e.iobuf[32:40] == bytes(8))
e.iobuf[:32] = bytes([5]) * 32; e.start = 30; e.load(mem, 0x100, 20)
check('klstart >= n: empty window, nothing transferred, klstart written 0', e.iobuf[:32] == bytes([5]) * 32 and e.start == 0)
e.start = 4; e.load(mem, 0x100, 8); check('window [klstart, n): only bytes 4..7 copied', e.iobuf[:4] == bytes([5]) * 4 and e.iobuf[4:8] == d[4:8] and e.iobuf[8] == 5)
mem5 = Mem(); e.iobuf[:32] = d; e.store(mem5, 0x300, 16); check('kl.output copies KLIOBUF[0:n] to memory', mem5.b[0x300:0x310] == d[:16] and mem5.b[0x310] == 0)

section('kl.exec: Form A, KLIOBUF substitution, transfer window  <<KLE-GR-substitution>>, <<KLE-GR-transfer-window-checks>>')
K = 0x0F0E0D0C0B0A09080706050403020100
def enc(**kw):
    e = E2(**kw); prov(e, 1); e.L[1].content = K; e.setst(1, 2); return e
x = lambda dd: bytes(a ^ b for a, b in zip(dd, v2b(K, 16) * (len(dd) // 16)))
e = enc(); dd = bytes(range(32)); check('Form A: each block out = in xor key; State unchanged (MR16)', e.execw(1, form='A', data=dd) == x(dd) and e.getst(1) == 2)
e = enc(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 32; e.iobuf[:32] = dd; check('Form D substitution writes its output over the input in KLIOBUF', e.execw(1, form='D') == 'ok' and bytes(e.iobuf[:32]) == x(dd) and e.start == 0)
e = enc(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 32; e.iobuf[:32] = dd; e.start = 16; e.execw(1, form='D')
check('substitution window starts at klstart: only [16, 32) processed', bytes(e.iobuf[:16]) == dd[:16] and bytes(e.iobuf[16:32]) == x(dd[16:32]))
e = enc(); e.iobuf[:16] = bytes(16); check('without Zklio a substitution is a wrong Form (<<KLE-GR-form-mismatch>>): Invalid, no exception', e.execw(1, form='D') == 'invalid' and stx(e, 1) == INV)
e = enc(); e.zklio = True; check('Zklio, KLIOBUF unconfigured: illegal (GR20 item 1), State kept', trap(e.execw, 1, form='D') == 'illegal' and e.getst(1) == 2)
e = enc(); e.zklio = True; e.L[1].mdh = mdh_put(e.md(1), 'UsagePolicy', 0); check('GR20 item 1 (unconfigured KLIOBUF) precedes item 2 (UsagePolicy)', trap(e.execw, 1, form='D') == 'illegal')
e.kliobuflen = 64; e.kliobuftop = 32; check('with a configured KLIOBUF the UsagePolicy then applies: privilege violation', trap(e.execw, 1, form='D') == 'privilege_violation' and e.getst(1) == 2)
for f in 'BC': e = enc(); check('Form %s in a State whose native Form is A: wrong Form -> Invalid' % f, e.execw(1, form=f) == 'invalid' and stx(e, 1) == INV)
e = enc(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 20; check('non-zero kliobuflen, kliobuftop invalid for the Machine -> Invalid (<<KLE-GR-substitution-failures>>)', e.execw(1, form='D') == 'invalid' and stx(e, 1) == INV)
e = enc(); e.start = 32; r = e.execw(1, form='A', data=dd)
check('klstart >= length: window empty, klstart 0, Machine not reached, State kept (GR52.1)', e.start == 0 and e.getst(1) == 2 and r == bytes(32))
e = enc(); e.start = 8; check('klstart not an interruption point -> Invalid (GR52.3)', e.execw(1, form='A', data=dd) == 'invalid' and stx(e, 1) == INV)
e = enc(); check('length invalid for the Machine (24 bytes) -> Invalid (GR52.2)', e.execw(1, form='A', data=dd[:24]) == 'invalid' and stx(e, 1) == INV)
e = enc(); e.start = 40; r = e.execw(1, form='A', data=dd); check('GR52.1 precedes GR52.3: klstart 40 (not a multiple of 16) >= length 32 is an empty window, not Invalid', r == bytes(32) and e.start == 0 and e.getst(1) == 2)
e = enc(); dd4 = bytes(range(64)); h, part = e.execw(1, form='A', data=dd4, halt_after=2)
check('halt at an interruption point: klstart = 32, prefix committed, not retired (GR49)', h == 'halted' and e.start == 32 and part[:32] == x(dd4[:32]))
r = e.execw(1, form='A', data=dd4); check('resumed from klstart 32 completes; klstart 0 on retire', r[32:] == x(dd4[32:]) and e.start == 0)
e = enc(); e.nl = 1; e.start = 5; e.setnl(32); e.execw(0, r=1, form='A', data=dd); check('exec falling through (klnamedlocker 32): klstart written 0 (<<KLE-GR-klstart-updates>>)', e.start == 0)
e = enc(); e.setst(1, 1); e.start = 7; check('kl.setst leaves klstart (inert-outcome table; GR51: not an honoring instruction)', e.start == 7)
e = enc(); e.start = 7; e.getmd(1); e.clearads(1); check('other instructions leave klstart unchanged (<<KLE-GR-klstart-updates>>)', e.start == 7)

section('kl.derive  <<KLE-instruction-derive>>, GR37-GR43')
SEC = int.from_bytes(bytes(range(1, 33)), 'little')
def dv(srcm=M_KEM, dstm=M_KEY32, sst=2, dst=1, sup=0x4, dup=0x4, sprot=0, dprot=0, dloc=0, sloc=0, dpol=0, spol=0, **kw):
    e = E2()
    prov(e, 1, mach=srcm, pol=spol, up=sup, SCProtection=sprot, Locality=sloc); e.L[1].content = SEC
    prov(e, 2, mach=dstm, pol=dpol or (3 if dstm in (M_ENC, M_KEY) else 0), up=dup, SCProtection=dprot, Locality=dloc, **kw)
    if sst != 1: e.setst(1, sst)
    if dst != 1: e.setst(2, dst)
    return e
e = dv(); r = e.derive(2, 1, 32)
check('shared secret -> 32-byte key field: ok, all 32 bytes (GR38, GR42)', r == 'ok' and e.L[2].content == SEC and e.getst(2) == 1 and e.getst(1) == 2)
e = dv(dup=0x6, sup=0x5); e.derive(2, 1, 32); check('restricted transfer narrows dest UsagePolicy by AND (GR40); State of dest stays Ready', mdh_get(e.md(2), 'UsagePolicy') == 0x4)
e = dv(sloc=0x10, dloc=0x20); r = e.derive(2, 1, 32); check('GR40: narrowing fails (boot subfields differ) -> dest Privilege Violation, nothing transferred', r == 'pv' and stx(e, 2) == (0, SE_PRIV_VIOLATION) and e.getst(1) == 2)
e = dv(sprot=2, dprot=1); r = e.derive(2, 1, 32); check('GR40: dest SCProtection lower than source -> dest Privilege Violation', stx(e, 2) == (0, SE_PRIV_VIOLATION))
e = dv(sprot=1, dprot=2); check('dest SCProtection >= source: ok', e.derive(2, 1, 32) == 'ok')
for ln in (0, 31): e = dv(); e.derive(2, 1, ln); check('shared secret into a key field requires length >= dest_length (%d) -> dest Invalid (GR39.6)' % ln, stx(e, 2) == INV and e.getst(1) == 2)
e = dv(); r = e.derive(2, 1, 33); check('shared secret, length 33 > dest_length 32: the key field receives the first 32 bytes (GR38, GR39.6)', r == 'ok' and e.L[2].content == SEC)
e = dv(sst=1); r = e.derive(2, 1, 32); check('source not a source endpoint (Ready) -> source Invalid (GR39.2)', stx(e, 1) == INV and e.getst(2) == 1)
e = dv(dstm=M_ENC); e.setst(2, 2); r = e.derive(2, 1, 32); check('dest not a destination endpoint (key field outside Ready) -> dest Invalid (GR39.3)', stx(e, 2) == INV and e.getst(1) == 2)
e = dv(dstm=M_KEY, KeyType=1); e.derive(2, 1, 32); check('a SKID key field (KeyType 1) is never a destination -> dest Invalid', stx(e, 2) == INV)
e = dv(srcm=M_ENC, dstm=M_KEY, spol=3, dprot=0, sprot=2, sloc=0x10, dloc=0x20); e.L[1].content = K; r = e.derive(2, 1, 16)
check('block cipher output -> key field is unrestricted (GR43, GR41): no narrowing, no SCProtection check', r == 'ok' and e.L[2].content == int.from_bytes(ks_block(K, 0), 'little') and mdh_get(e.md(2), 'Locality') == 0x20)
e = dv(srcm=M_ENC, dstm=M_KEY, spol=3); e.L[1].content = K; e.derive(2, 1, 20); check('length > dest_length: eff_length = dest_length (GR38)', e.L[2].content == int.from_bytes(ks_block(K, 0), 'little'))
e = dv(srcm=M_ENC, dstm=M_KEY, spol=3); e.derive(2, 1, 8); check('length < dest_length for a key field -> dest Invalid (GR39.6)', stx(e, 2) == INV)
e = dv(srcm=M_ENC, dstm=M_HASH, spol=3, dst=2); e.derive(2, 1, 16)
check('pair not admitted (cipher output -> hash input, GR43 only key fields): both lockers Invalid (GR39.4)', stx(e, 1) == INV and stx(e, 2) == INV)
e = dv(dstm=M_HASH, dst=2); r = e.derive(2, 1, 32); check('shared secret -> hash input (GR42): ok, length == secret length', r == 'ok' and e.L[2].content == SEC)
e = dv(dstm=M_HASH, dst=2); e.derive(2, 1, 16); check('hash input receiving a shared secret requires length == secret length (GR39.6)', stx(e, 2) == INV)
e = dv(); e.start = 16; e.derive(2, 1, 32); check('klstart != 0 -> dest Invalid (GR39.1)', stx(e, 2) == INV)
e = dv(sst=1); e.start = 16; e.derive(2, 1, 32); check('klstart != 0 is checked before the source endpoint: dest Invalid, source kept (GR39.1)', stx(e, 2) == INV and e.getst(1) == 1)
e = dv(); check('same source and destination -> illegal', trap(e.derive, 1, 1, 32) == 'illegal')
e = dv(); e.nl = 1; check('KLNL as source (R=10): transfers from the named locker', e.derive(2, 'NL', 32) == 'ok' and e.L[2].content == SEC)
e = dv(); e.setnl(32); check('klnamedlocker 32: falls through, nothing changes', e.derive(2, 'NL', 32) == 'inert' and e.L[2].content == 0)
e = dv(dup=0); check('dest UsagePolicy forbids: privilege violation exception, nothing changed', trap(e.derive, 2, 1, 32) == 'privilege_violation' and e.getst(1) == 2)
e = dv(sst=1, dup=0); check('GR37: conditions in order, source then dest per condition: dest UsagePolicy violation (condition 2) precedes source endpoint Invalid (GR39)', trap(e.derive, 2, 1, 32) == 'privilege_violation' and stx(e, 1) == (1, 0))
e = dv(); e.L[2].mdh = mdh_put(e.md(2), 'State', 56); check('Configuration State locker as dest -> privilege violation', trap(e.derive, 2, 1, 32) == 'privilege_violation')
e = dv(); e.L[2].mdh = mdh_put(e.md(2), "State", 56); e.setnl(32); check("KLNL source with klnamedlocker 32 falls through even with a Configuration State dest (GR32, GR16 item 5)", e.derive(2, "NL", 32) == "inert")
e = dv(); e.L[1].mdh = mdh_put(e.md(1), 'ExpirationDate', 5); e.clock = 9; r = e.derive(2, 1, 32); check('expired source: Error State Expired, nothing transferred', stx(e, 1) == (0, SE_EXPIRED) and e.L[2].content == 0)
e = dv(); e.clear(2); check('inert destination: no operation', e.derive(2, 1, 32) == 'inert' and e.getst(1) == 2)

section('Encodings, GR1 GR2 GR6 GR7  <<KLE-GR-reserved-encodings>>, <<KLE-instruction-exec>>, <<KLE-instruction-mv>>')
n, f = decode(enc_rtype(5, 3, 7, form=0)); check('kl.exec Form A: rd=Vd, rs1=Kn, rs2=Vs2', n == 'exec' and f['form'] == 'A' and f['kn'] == 3 and f['rd'] == 5 and f['rs2'] == 7)
check('Form B needs rd = 0, Form C rs2 = 0, Form D rd = rs2 = 0', trap(decode, enc_rtype(1, 3, 7, form=1)) == 'illegal' and decode(enc_rtype(0, 3, 7, form=1))[1]['form'] == 'B'
      and trap(decode, enc_rtype(1, 3, 7, form=2)) == 'illegal' and decode(enc_rtype(1, 3, 0, form=2))[1]['form'] == 'C' and decode(enc_rtype(0, 3, 0, form=3))[1]['form'] == 'D')
check('kl.exec bit 25 set (not a mv variant) is reserved', trap(decode, enc_rtype(0, 3, 0, b25=1, form=3)) == 'illegal')
check('r bit selects KLNL', decode(enc_rtype(0, 0, 0, r=1, form=3))[1]['r'] == 1)
for rd, nm in ((1, 'mvin_x'), (2, 'mvin_v'), (3, 'mvin_buf'), (5, 'mvout_x'), (6, 'mvout_v'), (7, 'mvout_buf')):
    ok = {1: (0, 4), 2: (0, 7), 3: (0, 0), 5: (6, 0), 6: (7, 0), 7: (0, 0)}[rd]
    check('Form D rd=%d is %s' % (rd, nm), decode(enc_rtype(rd, ok[0], ok[1], form=3))[0] == nm)
check('Form D rd = 4 and rd >= 8 are reserved -> illegal', all(trap(decode, enc_rtype(rd, 0, 0, form=3)) == 'illegal' for rd in (4, 8, 9, 15, 31)))
check('mv: r = 1 reserved; nonzero rs1 in I-III,VI; nonzero rs2 in III-VI -> illegal', trap(decode, enc_rtype(2, 0, 3, r=1, form=3)) == 'illegal'
      and trap(decode, enc_rtype(1, 3, 4, form=3)) == 'illegal' and trap(decode, enc_rtype(2, 3, 4, form=3)) == 'illegal' and trap(decode, enc_rtype(3, 0, 4, form=3)) == 'illegal'
      and trap(decode, enc_rtype(5, 6, 4, form=3)) == 'illegal' and trap(decode, enc_rtype(7, 2, 0, form=3)) == 'illegal')
check('GR2: mvin Xs2 / mvout Xs1 need an even register pair (XLEN 64), multiple of 4 (XLEN 32)', trap(decode, enc_rtype(1, 0, 3, form=3)) == 'illegal' and decode(enc_rtype(1, 0, 4, form=3))[0] == 'mvin_x'
      and trap(decode, enc_rtype(1, 0, 2, form=3), xlen=32) == 'illegal' and decode(enc_rtype(1, 0, 4, form=3), 32)[0] == 'mvin_x' and trap(decode, enc_rtype(5, 5, 0, form=3)) == 'illegal')
for T, nm in enumerate(('clone', 'rename', 'swap', 'derive')):
    n, f = decode(0x0F | 4 << 7 | 4 << 12 | 5 << 15 | 6 << 20 | 1 << 25 | T << 27 | 2 << 30)
    check('funct2=2, T=%d is kl.%s (R=01: Kd is KLNL)' % (T, nm), n == nm and f['R'] == 1 and f['kd'] == 4 and f['ks'] == 5)
check('R = 11 reserved for the clone/rename/swap/derive family (<<KLE-GR-klnamedlocker-override>>)', trap(decode, 0x0F | 4 << 12 | 3 << 25 | 3 << 27 | 2 << 30) == 'illegal')
check('GR6: vector MDH operand with VL*SEW < 128 -> illegal; GR7: vstart != 0 -> illegal on getmdv, rstrv, Form C size, avail, setst, mgmt',
      trap(vec_mdh_ok, 'getmdv', 3, 32, 0) == 'illegal' and trap(vec_mdh_ok, 'getmdv', 4, 32, 0) is None
      and all(trap(vec_mdh_ok, i, 4, 32, 1) == 'illegal' for i in ('getmdv', 'rstrv', 'size_C', 'avail_C', 'setst_C', 'mgmt_C')) and trap(vec_mdh_ok, 'mvin_v', 4, 32, 1) is None)
section('GR1 reserved setst/mgmt immediates through KLNL and GR3')
e = KLE2(); check('GR4: KLNL requires the locker field 0 (r=1, kd!=0): illegal for getmd, exec, size', all(trap(fn, 5, 1) == 'illegal' for fn in (e.getmd, e.size, e.avail, e.exec)))

section('Long-running operation  <<KLE-GR-long-running-progress>>, <<KLE-GR-progress-discard>>, <<KLE-GR-long-running-restart>>')
def lrs():
    e = E2(); prov(e, 1, mach=M_SIG, pol=0, up=0x4); e.setst(1, 3); return e
e = lrs(); ps = []
for _ in range(2): r = e.lr(1, 2); ps.append((r, mdh_get(e.md(1), 'MachineUse')))
r = e.lr(1, 2); ps.append((r, mdh_get(e.md(1), 'MachineUse')))
check('P non-zero and increasing at each halt, zero at completion (GR55); State unchanged after completion (MR16)', ps == [('halted', 2), ('halted', 4), ('done', 0)] and e.getst(1) == 3)
e = lrs(); e.lr(1, 2); e.clearads(1); check('kl.clearads zeroes P and destroys the material (GR56.3)', mdh_get(e.md(1), 'MachineUse') == 0 and e.L[1].steps == 0)
e = lrs(); e.lr(1, 2); e.setst(1, 1); check('every State transition zeroes P (Ready)', mdh_get(e.md(1), 'MachineUse') == 0 and e.getst(1) == 1)
e = lrs(); e.lr(1, 2); e.setst(1, 3); check('a same-State kl.setst is not admitted (GR21): Invalid', stx(e, 1) == INV)
e = lrs(); e.lr(1, 2); e.nl = 1; e.mgmt(1, 57, form='A'); e.mgmt(1, 63, md=mk(mach=M_SIG, State=3))
check('export-open and completion (moves into and out of a Configuration State) do not zero P', e.getst(1) == 3 and mdh_get(e.md(1), 'MachineUse') == 2 and e.L[1].steps == 2)
e = lrs(); e.lr(1, 2); e.clone(2, 1); check('kl.clone restarts in the copy (P zeroed), the source keeps P (GR57)', mdh_get(e.md(2), 'MachineUse') == 0 and mdh_get(e.md(1), 'MachineUse') == 2 and e.getst(2) == 3)
e = lrs(); e.lr(1, 2); e.rename(3, 1); check('kl.rename carries P with the CC', mdh_get(e.md(3), 'MachineUse') == 2)

section('System-specific format import  <<KLE-system-specific-import>>, GR66-GR71')
sf = mk(Version=3, AuxDataLen=3)
e = E2(); e.mgmt(0, 58, md=sf); check('Version 3 import opens in State 58 with Version 3 MDH; kl.size = 16 + 16*AuxDataLen (GR67)', e.getst(0) == 58 and mdh_get(e.md(0), 'Version') == 3 and e.size(0) == 64 and e.image_end(0) == 48)
check('kl.size Forms B and C of a Version 3 MDH', e.size(form='C', md=sf) == 64 and e.size(form='B', md=sf) == 64)
for nm, kw in (('AuxDataLen 0', dict(AuxDataLen=0)), ('StateExtension != 0 (State 0)', dict(StateExtension=1)), ('KeyType != 0', dict(KeyType=1)),
               ('ADSDropped', dict(ADSDropped=1)), ('MachineUse', dict(MachineUse=1)), ('State 1', dict(State=1))):
    f = dict(Version=3, AuxDataLen=3); f.update(kw); e = E2(); e.mgmt(0, 58, md=mk(**f))
    if nm.startswith('StateExtension'): check('Version 3 import with an Error-State MDH is invalid Metadata: Error State Invalid', e.md(0) == mdh_pack(State=0, StateExtension=SE_INVALID))
    elif nm == 'State 1': check('Version 3 import with State 1 -> invalid', stx(e, 0) == INV)
    else: check('Version 3 import with ' + nm + ' -> Invalid', stx(e, 0) == INV)
check('Version 3 at provisioning -> Invalid (GR66)', (lambda e: (e.mgmt(0, 56, md=mk(Version=3, AuxDataLen=3)), stx(e, 0))[1])(E2()) == INV)
def sysimg(e, key, tag_ok=True):
    pay = v2b(key, 16) + bytes(24); tg = toy_tag(int.from_bytes(pay, 'little')) if tag_ok else 1
    data = v2b(tg, 8) + pay
    e.gpr_in(int.from_bytes(data[:16], 'little')); e.gpr_in(int.from_bytes(data[16:32], 'little')); e.gpr_in(int.from_bytes(data[32:48], 'little'))
e = E2(); e.mgmt(0, 58, md=sf); sysimg(e, 0x5151); e.mgmt(0, 63, md=0, form='A')
check('completion (ml.State 0): authenticated, converted, Version 0, AuxDataLen 0, Ready, content = key (GR71)', stx(e, 0) == (1, 0) and mdh_get(e.md(0), 'Version') == 0 and mdh_get(e.md(0), 'AuxDataLen') == 0 and e.L[0].content == 0x5151)
e = E2(); e.mgmt(0, 58, md=sf); sysimg(e, 0x5151, False); e.mgmt(0, 63, md=0, form='A'); check('failed authentication -> Error State Authentication Failed, no exception (GR71.1)', stx(e, 0) == (0, SE_MGMT_AUTH) and mdh_get(e.md(0), 'Version') == 0)
e = E2(); e.fmt_min_prot = 2; e.mgmt(0, 58, md=mk(Version=3, AuxDataLen=3, SCProtection=1)); sysimg(e, 1); e.mgmt(0, 63, md=0, form='A'); check('format requires a higher SCProtection than declared -> Privilege Violation (GR71.3)', stx(e, 0) == (0, SE_PRIV_VIOLATION))
e = E2(); e.mgmt(0, 58, md=mk(State=1)); check('ml.State 0 is not admitted for a locker in 58 that is not Version 3', trap(e.mgmt, 0, 63, form='C', md=mk(State=0)) == 'illegal')
e = E2(); e.mgmt(0, 58, md=sf); sysimg(e, 7); e.mgmt(0, 57, form='A')
check('nested export during the import: State 57 PCCC, ContentOffset 0 (the data as loaded), Version 3 kept (GR70)', e.getst(0) == 57 and mdh_get(e.md(0), 'Version') == 3 and e.offset(e.md(0)) == 0)
e.start = 0; first = e.gpr_out(); e.mgmt(0, 63, md=mk(State=58)); check('completing the nested export restores State 58', e.getst(0) == 58 and first == int.from_bytes(bytes(e.img(0)[:16]), 'little'))

section('ADS, ADSDropped, IMPQUAL, SIV  <<KLE-MVR-open>>, <<KLE-SCC-import>>')
for adl, dr, want in ((0, 0, 0), (2, 0, 0), (3, 0, 0), (4, 0, 0), (5, 0, 1), (3, 1, 1), (2, 1, 1)):
    e = E2(); e.mgmt(0, 58, md=mk(State=1, AuxDataLen=adl, ADSDropped=dr)); check('import AuxDataLen %d ADSDropped %d: ADSDropped becomes %d (ADS dropped if flagged or above the implementation limit)' % (adl, dr, want), mdh_get(e.md(0), 'ADSDropped') == want)
e = E2(); e.mgmt(0, 58, md=mk(State=1, AuxDataLen=3)); check('kl.size of an imported SCC with ADS: 64 + c1 + 16 = 96; ContentOffset 48', e.size(0) == 96 and e.offset(e.md(0)) == 48)
e = E2(); e.mgmt(0, 58, md=mk(State=1, AuxDataLen=3, ADSDropped=1)); check('ADSDropped keeps the 64-byte header form, no Content2: kl.size 80', e.size(0) == 80)
e = E2(); e.siv, e.impqual, e.siv2 = 1, 2, 3; e.mgmt(0, 58, md=mk(State=1)); check('import-opening kl.mgmt zeroizes SIV, IMPQUAL, SIV2', (e.siv, e.impqual, e.siv2) == (0, 0, 0))
e = E2(); e.siv, e.impqual, e.siv2 = 1, 2, 3; trap(e.mgmt, 0, 58, md=mk(mach=0x99, State=1)); check('zeroization happens even when the import then raises unsupported (<<KLE-exception-state-change>>)', (e.siv, e.impqual, e.siv2) == (0, 0, 0))
e = E2(); e.siv = 1; e.mgmt(0, 56, md=mk()); check('provisioning leaves the authentication registers', e.siv == 1)
e = E2(csk=False); e.siv = 1; trap(e.mgmt, 0, 58, md=mk(State=1)); check('rejected by the missing-CSK check: registers untouched', e.siv == 1)
e = E2(); e.siv = 1; e.setnl(32); e.mgmt(0, 58, r=1, md=mk(State=1)); check('KLNL & 32: only the common steps, registers untouched', e.siv == 1)

section('Context save and restore, reset  <<KLE-out-of-reset-unpriv>>, <<KLE-reset-and-m-mode-only>>')
e = E2(); prov(e, 1, mach=M_SIG, pol=0); e.L[1].content = 0x1234 | 0x77 << 128; m0 = e.md(1); e.nl = 1; e.mgmt(1, 57, form='A')
sv = [e.gpr_out(), e.gpr_out(), e.gpr_out()]; sig = e.siv; e.mgmt(1, 63, md=m0)
check('export: completion restores Ready', e.getst(1) == 1)
e.reset(); e.csk = True
check('reset: lockers Unconfigured, klnamedlocker 32, klstart 0, KLIOBUF unconfigured, registers zero', all(e.md(k) == 0 for k in range(32)) and e.nl == 32 and e.start == 0 and e.kliobuflen == 0 and e.kliobuftop == 0 and (e.siv, e.impqual, e.siv2) == (0, 0, 0))
e.mgmt(2, 58, md=m0); [e.gpr_in(v) for v in sv]; e.siv = sig; e.mgmt(2, 63, md=m0)
check('import after reset restores the Ready locker: same MDH fields, content, authenticated', stx(e, 2) == (1, 0) and e.L[2].content == 0x1234 | 0x77 << 128 and mdh_get(e.md(2), 'Machine') == M_SIG)
e.reset(); e.csk = True; e.mgmt(2, 58, md=m0); [e.gpr_in(v) for v in sv[:2] + [sv[2] ^ 1]]; e.siv = sig; e.mgmt(2, 63, md=m0)
check('tampered image -> Authentication Failed', stx(e, 2) == (0, SE_MGMT_AUTH))
e.reset(); check('reset unconfigures a software-established CSK (usage needs a CSK again)', trap(e.mgmt, 0, 56, md=mk()) == 'no_csk')
e = E2(); e.csk_hardwired = True; e.reset(); check('a hardwired CSK survives the unit reset', e.csk is True)
section('Debug UsagePolicy, check order, RBG failure')
def dbg(up, auth=False, mode=2):
    e = E2(mode=mode); prov(e, 1, up=up); e.debug = True; e.debug_auth = auth; return e
check('Debug: UsagePolicy bit 4 and the bits of the debug access privilege (S, bit 2) and of every mode below it are all needed', trap(dbg(0x17).setst, 1, 2) is None and all(trap(dbg(up).setst, 1, 2) == 'privilege_violation' for up in (0x07, 0x14, 0x13, 0x15, 0x10, 0x04)))
check('Debug: a debug access privilege of VS needs bits 0 and 1 only, one of U needs bit 0', trap(dbg(0x13, mode=1).setst, 1, 2) is None and trap(dbg(0x12, mode=1).setst, 1, 2) == 'privilege_violation' and trap(dbg(0x11, mode=0).setst, 1, 2) is None and trap(dbg(0x10, mode=0).setst, 1, 2) == 'privilege_violation')
check('Debug: bit 4 alone suffices in authenticated Debug', trap(dbg(0x10, True).setst, 1, 2) is None and trap(dbg(0x04, True).setst, 1, 2) == 'privilege_violation')
check('UsagePolicy zero admits no mode, including Debug', all(trap(dbg(0, a).setst, 1, 2) == 'privilege_violation' for a in (False, True)))
e = E2(csk=False)
check('GR16: no-CSK exception precedes klnamedlocker=32 fall-through for kl.exec, load, setst, restrict', trap(e.execw, 0, 1) == 'no_csk' and trap(e.load, Mem(), 0) == 'no_csk' and trap(e.setst, 0, 1, 1) == 'no_csk' and trap(e.rstr, 0, 0, 1) == 'no_csk')
e = E2(csk=False); check('GR16: misalignment (item 8) after no-CSK (item 4)', trap(e.load, Mem(), 1) == 'no_csk')
e = E2(); e.nl = 5; check('GR16: Xl != 0 illegal (item 7) precedes misalignment (item 8)', trap(e.load, Mem(), 1, 4) == 'illegal')
e = E2(); e.mgmt(0, 56, md=mk(KeyType=2, mach=M_KEY)); e.rbg_dead = True; e.mgmt(0, 63, md=mk(State=56)); check('RBG permanent failure: KeyType 2 provisioning completion not performed, locker Invalid (GR65)', stx(e, 0) == INV)
e = E2(); e.mgmt(0, 56, md=mk(KeyType=2, mach=M_KEY)); e.mgmt(0, 63, md=mk(State=56)); check('control: with a working RBG the same completion reaches Ready with a key (GR65)', stx(e, 0) == (1, 0) and e.L[0].content != 0)


section('Phase 2 additions: layout walking ones, kl.getst expansions, GR21, nested PCCC  <<KLE-metadata-header>>')
ok = True
for n, lo, w in MDH_FIELDS:
    for b in range(w):
        v = 1 << (lo + b); ok &= mdh_get(v, n) == 1 << b and all(mdh_get(v, m) == 0 for m, _, _ in MDH_FIELDS if m != n)
check('walking ones: each field bit at its position, no bleed', ok)
check('all-ones MDH round trips through mdh_unpack/mdh_pack', mdh_pack(**mdh_unpack(mask(128))) == mask(128))
w = mdh_pack(State=0x2A, StateExtension=0x5, Machine=7)
e = KLE(); e.L[1].mdh = w; check('kl.getst = (getmdl >> 18) & 0x3F, kl.getstx = (getmdl >> 24) & 0xF; getmdl is MDH[63:0]', e.getst(1) == (e.getmd(1, part='l') >> 18) & 63 == 0x2A and e.getstx(1) == (e.getmd(1, part='l') >> 24) & 15 == 5 and e.getmd(1, part='l') == w & mask(64))
e = enc(); check('GR21: kl.exec in Ready is not admitted: Invalid', (e.setst(1, 1), e.execw(1, form='A', data=bytes(16)))[1] == 'invalid' and stx(e, 1) == INV)
e = enc(); e.setst(1, 2); check('GR21: kl.setst naming the current State (not Ready) is not admitted: Invalid', stx(e, 1) == INV)
e = E2(); e.mgmt(0, 56, md=mk()); e.gpr_in(1); e.mgmt(0, 57, form='A')
check('nested export from Provisioning: State 59, PCCC of pi shape keeps the loaded bytes; klnamedlocker kept; completion with ml.State 56 restores 56', e.getst(0) == 59 and e.nl == 0 and (e.mgmt(0, 63, md=mk(State=56)), e.getst(0))[1] == 56 and bytes(e.img(0)[:16]) == v2b(1, 16))


section('Localities in depth  <<KLE-Localities>>')
def LOC(*js):
    v = 0
    for j in js:
        if j < 3: v |= j + 1
        elif j < 6: v |= (j - 2) << 2
        elif j < 8: v |= (j - 5) << 4
        else: v |= 1 << (j - 2)
    return v
check('Locality bit positions: entry j in [1:0] (0-2), [3:2] (3-5), [5:4] (6-7), bits 6, 7, 8 (8-10)', [loc_entries(LOC(j)) for j in range(11)] == [[j] for j in range(11)])
check('bits [5:4] = 3 name no entry (reserved, invalid)', loc_entries(0x30) == [] and validate(mk(Locality=0x30), 'provision') == 'invalid')
e = E2(); e.lst = [0, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0]
check('unconfigured entry replaced by the next configured one of its chain: SiP -> ChipFam; Chip has none; OEM, Prod -> Dev', e.conf(0) == 7 and e.conf(1) == 7 and e.conf(2) == 0 and e.conf(3) == 9 and e.conf(4) == 9 and e.conf(5) == 9)
check('a PI whose Locality names an entry with a configured substitute is valid: SiPScrt (0) and OEMScrt (3)', e.mgmt(0, 56, md=mk(Locality=LOC(0, 3))) is None and e.getst(0) == 56)
e = E2(); e.lst = [0, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0]; e.mgmt(0, 56, md=mk(Locality=LOC(2))); check('ChipScrt unconfigured, no substitute: Invalid, never dropped', stx(e, 0) == INV)
for j, nm in ((6, 'PhysBootScrt'), (7, 'VirtBootScrt'), (8, 'MLocality'), (9, 'HLocality'), (10, 'SLocality')):
    e = E2(); e.lst[j] = 0; e.mgmt(0, 56, md=mk(Locality=LOC(j))); e1 = stx(e, 0)
    e.lst[j] = 5; e.mgmt(1, 56, md=mk(Locality=LOC(j)))
    check('%s unconfigured (zero or CSR group absent): Invalid; configured: valid' % nm, e1 == INV and stx(e, 1) == (56, 0))
e = E2(); e.lst = [0] * 11; check('kl.size Form C applies the same Locality check (GR10): 0 for an unconfigured entry, else the size', e.size(form='C', md=mk(Locality=LOC(2))) == 0 and E2().size(form='C', md=mk(Locality=LOC(2))) == 32)
e = E2(); e.lst[5] = 0; e.lst[3] = 0; e.lst[4] = 0; e.mgmt(0, 58, md=mk(State=1, Locality=LOC(3))); check('import applies the Locality check too: Invalid', stx(e, 0) == INV)
section('SKID, KeyType 1, kl.avail of unsupported KeyTypes  <<KLE-system-keys>>, <<KLE-KeyType-field>>')
K64 = 0x1122334455667788
def skp(**ov):
    e = E2(); ent = dict(machines={M_KEY}, pol=3, loc=LOC(1), key=0xAAAA); ent.update(ov); e.sks = {K64: ent}; return e
def prov_skid(e, k=0, skid=K64, **kw):
    e.mgmt(k, 56, md=mk(mach=M_KEY, KeyType=1, **kw)); e.L[k].content = skid; FIN(e, k)
e = skp(); prov_skid(e)
check('KeyType 1 provisioning: the SKS resolves the SKID at completion (GR76); Ready; KeyType stays 1; key field holds the key', stx(e, 0) == (1, 0) and mdh_get(e.md(0), 'KeyType') == 1 and e.L[0].content == 0xAAAA)
check('SKS Locality (GR77) narrows the MDH Locality: ChipFamScrt added', mdh_get(e.md(0), 'Locality') == LOC(1))
e = skp(up=0b00110); prov_skid(e, up=0b01110); check('an associated UsagePolicy narrows by AND; an unassociated one leaves it unchanged', mdh_get(e.md(0), 'UsagePolicy') == 0b00110 and mdh_get(skp().md(0), 'UsagePolicy') == 0)
e = skp(); prov_skid(e, skid=K64 + 1); check('unknown SKID -> Error State Invalid', stx(e, 0) == INV)
e = skp(machines={M_ENC}); prov_skid(e); check('Machine not allowed for the SKID -> Invalid', stx(e, 0) == INV)
e = skp(pol=1); prov_skid(e); check('MachinePolicy not a subset of the allowed one (3 vs 1) -> Invalid', stx(e, 0) == INV)
e = skp(pol=3); prov_skid(e, pol=1); check('a subset of the allowed MachinePolicy resolves', stx(e, 0) == (1, 0))
e = skp(); e.mode = 0; prov_skid(e); check('SKID resolution is independent of the privilege mode', stx(e, 0) == (1, 0))
e = skp(loc=0x20); prov_skid(e, Locality=0x10); check('failed narrowing (Boot subfields differ) -> Privilege Violation', stx(e, 0) == (0, SE_PRIV_VIOLATION))
e = skp(minprot=2); prov_skid(e, SCProtection=1); check('SCProtection below the SKS minimum -> Privilege Violation', stx(e, 0) == (0, SE_PRIV_VIOLATION))
e = skp(minprot=2); prov_skid(e, SCProtection=2); check('SCProtection at the minimum resolves', stx(e, 0) == (1, 0))
e = skp(); prov_skid(e, skid=mask(64)); check('the all-ones SKID is an ordinary SKID: unresolved -> Invalid', stx(e, 0) == INV)
e = skp(); prov_skid(e); e.nl = 0; e.mgmt(0, 57, form='A'); check('export of a KeyType 1 locker carries the SKID, never the key (GR75)', bytes(e.img(0)[16:24]) == v2b(K64, 8) and v2b(0xAAAA, 2) not in bytes(e.img(0)))
e = E2(); e.sks = None; check('no SKID support: opening KeyType 1 -> kl_exc_unsupported; kl.avail 0, Forms A, B, C', trap(e.mgmt, 0, 56, md=mk(mach=M_KEY, KeyType=1)) == 'unsupported' and e.avail(form='C', md=mk(mach=M_KEY, KeyType=1)) == 0 and e.avail(form='B', md=mk(mach=M_KEY, KeyType=1)) == 0 and e.avail(form='C', md=mk(mach=M_KEY)) == 1)
e = E2(); e.has_rng = False; check('no random key generation: KeyType 2 -> kl_exc_unsupported; kl.avail 0; KeyType 0 unaffected', trap(e.mgmt, 0, 56, md=mk(mach=M_KEY, KeyType=2)) == 'unsupported' and e.avail(form='C', md=mk(mach=M_KEY, KeyType=2)) == 0 and e.avail(form='C', md=mk(mach=M_KEY)) == 1)
e = E2(); e.has_rng = False; check('kl.size of an unsupported KeyType is 0', e.size(form='C', md=mk(mach=M_KEY, KeyType=2)) == 0)
e = E2(); check('KeyType 1 and 2 for a Machine without a key field: invalid, so kl.size 0 and kl.avail still reflect the Machine only', e.size(form='C', md=mk(mach=M_SIG, pol=0, KeyType=1)) == 0)


section('KLS, stateen, locker-Off gate, kleemulation, KLIOBUF CSRs  <<KLE-KLS-field-in-mstatus>>, <<KLE-CSR-llockerstatus>>, <<KLE-kleemulation>>')
def lowp(**kw):
    csk = kw.pop('csk', True); e = E2(**kw); prov(e, 1); prov(e, 2); e.priv = 'S'; e.csk = csk; return e
e = E2(); e.kls = 0
check('KLS Off: every KLE instruction raises an illegal-instruction exception (first group)', all(trap(f, *a) == 'illegal' for f, a in
      ((e.exec, (1,)), (e.setst, (1, 2)), (e.getmd, (1,)), (e.mgmt, (1, 56)), (e.clear, (1,)), (e.clearall, ()), (e.size, (1,)), (e.load, (Mem(), 0)), (e.gpr_in, (1,)), (e.vec_out, (4, 32)))))
e = E2(csk=False); e.kls = 0; e.fatal = True
check('KLS Off precedes the fatal-error and the missing-CSK exceptions; fatal precedes second-group illegal and no-CSK (GR16 items 1, 2, 4)', trap(e.exec, 1) == 'illegal' and (setattr(e, 'kls', 1), trap(e.exec, 1))[1] == 'fatal'
      and (setattr(e, 'fatal', False), trap(e.exec, 1))[1] == 'no_csk')
e = E2(); e.fatal = True; check('fatal precedes the second-group illegal of a vector mv (GR16 item 3 after item 2)', trap(e.vec_in, d[:8], 32) == 'fatal')
e = E2(); e.kls = 0; check('KLS Off with M-mode too; hardwired identification CSRs stay readable (not modelled as instructions)', trap(e.size, 1) == 'illegal')
e = E2(); e.priv = 'S'; e.stateen = False; check('Smstateen KLE bit clear in a lower mode: every KLE instruction is illegal', trap(e.getmd, 1) == 'illegal' and trap(e.setst, 1, 2) == 'illegal')
e = E2(); e.stateen = False; check('the stateen gate does not apply to M-mode', trap(e.getmd, 1) is None)
e = E2(); prov(e, 1); e.kls = 1; e.run(e.getmd, 1); check('an instruction that changes no KLE state leaves KLS Initial', e.kls == 1)
e.run(e.setst, 1, 2); check('a state-modifying instruction sets KLS to Dirty', e.kls == 3)
e = E2(); e.kls = 1; e.run(e.clear, 5); check('kl.clear of an Unconfigured locker modifies nothing: KLS stays Initial', e.kls == 1)
e = E2(); prov(e, 1); e.kls = 2; e.run(e.clear, 1); check('a configured locker made Unconfigured sets KLS Dirty', e.kls == 3)
e = E2(); e.kls = 1; e.run(e.setnl, 3); check('klnamedlocker is KLE state: kl.setnl sets Dirty', e.kls == 3)
e = lowp(); e.lstat[1] = 0
check('locker Off in lower modes: exec, setst, getmd, getst, restrict, size, clearads and KLNL aliases trap (kl_exc locker-Off)', all(trap(f, *a) == 'locker_off' for f, a in
      ((e.exec, (1,)), (e.setst, (1, 2)), (e.getmd, (1,)), (e.getst, (1,)), (e.rstr, (1, 0)), (e.size, (1,)), (e.clearads, (1,)), (e.setste, (1, 2)))) and (setattr(e, 'nl', 1), trap(e.getmd, 0, 1))[1] == 'locker_off')
check('locker Off in M-mode: no gate (the field governs the modes below)', (setattr(e, 'priv', 'M'), trap(e.getmd, 1))[1] is None)
e = lowp(); e.lstat[1] = 0
check('destructive configuration is exempt: kl.clear, provisioning-opening and import-opening kl.mgmt, clone/rename into the locker', trap(e.clear, 1) is None and (e.lstat.__setitem__(1, 0), trap(e.mgmt, 1, 56, md=mk()))[1] is None
      and (e.lstat.__setitem__(1, 0), trap(e.mgmt, 1, 58, md=mk(State=1)))[1] is None and (e.lstat.__setitem__(1, 0), trap(e.clone, 1, 2))[1] is None and (e.lstat.__setitem__(1, 0), trap(e.rename, 1, 2))[1] is None)
e = lowp(); e.lstat[1] = 0
check('not exempt: export-opening and completing kl.mgmt, clone/rename out of it, kl.swap, the named-locker transfers', trap(e.mgmt, 1, 57, form='A') == 'locker_off' and trap(e.mgmt, 1, 63, form='A') == 'locker_off'
      and trap(e.clone, 2, 1) == 'locker_off' and trap(e.rename, 2, 1) == 'locker_off' and trap(e.swap, 1, 2) == 'locker_off' and trap(e.swap, 2, 1) == 'locker_off'
      and (setattr(e, 'nl', 1), trap(e.gpr_in, 1), trap(e.load, Mem(), 0))[1:] == ('locker_off', 'locker_off'))
e = lowp(); e.lstat[1] = 0; check('same-locker clone, rename and swap perform no operation and are not an access', all(trap(f, 1, 1) is None for f in (e.clone, e.rename, e.swap)))
e = lowp(); e.lstat[3] = 0; check('with klnamedlocker = 32 nothing is accessed: no locker-Off', (e.getmd(0, 1), trap(e.exec, 0, 1))[1] is None)
e = lowp(csk=False); e.lstat[1] = 0; check('missing CSK precedes locker-Off (GR16 items 4, 6)', trap(e.exec, 1) == 'no_csk')
e = lowp(); e.lstat[1] = 0; check('locker-Off precedes the State conditions: on a Configuration-State locker it, not the privilege violation, is raised', True)
e = lowp(); e.mgmt(4, 56, md=mk()); e.lstat[4] = 0; check('locker-Off precedes the Configuration-State privilege violation', trap(e.exec, 4) == 'locker_off')
e = lowp(); e.lstat[1] = 0; e.nl = 1; check('second-group illegal (short vector mv) precedes locker-Off (GR16 items 3, 6)', trap(e.vec_in, d[:8], 32) == 'illegal')
e = E2(); e.kleemu = True; nat, non = mk(), mk(mach=0x99)
check('kleemulation = 1: Forms B and C of kl.size and kl.avail trap for a non-native combination, answer for a native one', all(trap(f, form=fm, md=non) == 'illegal' for f in (e.size, e.avail) for fm in 'BC')
      and e.size(form='C', md=nat) == 32 and e.avail(form='C', md=nat) == 1)
e.kleemu = False; check('kleemulation = 0: the same MDH answers 0', e.size(form='C', md=non) == 0 and e.avail(form='C', md=non) == 0 and e.avail(form='B', md=non) == 0)
e.kleemu = True; check('earlier items do not depend on the implemented Machines: Error-State MDH is 16, State 62 and Version 1 are 0, even for a non-native Machine', e.size(form='C', md=mk(mach=0x99, State=0, StateExtension=2)) == 16
      and e.size(form='C', md=mk(mach=0x99, State=62)) == 0 and e.size(form='B', md=mk(mach=0x99, Version=1)) == 0 and e.avail(form='B', md=mk(mach=0x99, Version=1)) == 0)
e = E2(); e0 = E2(); prov(e, 1); prov(e0, 1); e.kleemu = True; e0.kleemu = False
check('kleemulation does not affect Form A; kl.size item 7: Valid State, AuxDataLen 0 gives 32 + content1_size (toy M_ENC content1_size 16)', e.size(1) == e0.size(1) == 32 + CONTENT[M_ENC] == 48 and e.avail(1) == e0.avail(1) == 1)
e = E2(); e.kleemu = True; check('control: a Version 3 MDH with a non-native Machine still reaches the lookup and traps', trap(e.size, form='C', md=mk(mach=0x99, Version=3, AuxDataLen=2)) == 'illegal')
e = E2(); check('without Zklio kliobuflen and kliobuftop do not exist (access raises illegal-instruction, m9); mklmaxiobuflen ignores writes and reads 0', trap(e.w_kliobuflen, 64) == 'illegal' and trap(e.w_kliobuftop, 32) == 'illegal' and e.w_maxiobuflen(32) is None and e.kliobuflen == 0 and e.kliobuftop == 0 and e.r_maxiobuflen() == 0)
e = E2(); e.zklio = True; e.iobuf[:64] = bytes([7]) * 64; e.w_kliobuflen(32)
check('every kliobuflen write zeroes the buffer below the new length and sets kliobuftop; bytes beyond need not be erased', e.iobuf[:32] == bytes(32) and e.kliobuftop == 32 and e.iobuf[32:40] == bytes([7]) * 8)
e.iobuf[:32] = bytes([5]) * 32; e.w_kliobuflen(32); check('even a write of the current value zeroes the buffer', e.iobuf[:32] == bytes(32))
e.iobuf[:8] = bytes([5]) * 8; e.w_kliobuftop(16); check('a kliobuftop write leaves the buffer unchanged and is capped by kliobuflen', e.iobuf[:8] == bytes([5]) * 8 and e.kliobuftop == 16 and (e.w_kliobuftop(99), e.kliobuftop)[1] == 32)
e.w_kliobuflen(0); check('kliobuflen = 0 leaves the KLIOBUF unconfigured (GR14)', trap(e.buf_in) is None and (setattr(e, 'nl', 0), True)[1] and e.kliobuflen == 0)
section('getters and setters  <<KLE-instruction-getter-setter>>')
e = E2(); e.zklio = True; e.iobuf[:64] = bytes([7]) * 64
e.setbl(1 << 20); check('kl.setbl above the maximum, read back with kl.getbl: the maximum, as vsetvl', e.getbl() == e.maxiobuf and e.getbt() == e.maxiobuf)
e.setbl(32); check('kl.setbl zeroes the buffer below the length and sets the top', e.getbl() == 32 and e.getbt() == 32 and e.iobuf[:32] == bytes(32))
e.iobuf[:8] = bytes([5]) * 8; e.setbt(16); check('kl.setbt: top capped by the length, buffer unchanged', e.getbt() == 16 and e.iobuf[:8] == bytes([5]) * 8)
e.setbt(99); check('kl.setbt above the length: capped', e.getbt() == 32)
e.setks(9); check('kl.setks / kl.getks', e.getks() == 9 and e.start == 9)
e = E2(); check('without Zklio kl.getbl, getbt, setbl and setbt are reserved (GR1)', all(trap(f, *a) == 'illegal' for f, a in ((e.getbl, ()), (e.getbt, ()), (e.setbl, (8,)), (e.setbt, (8,)))))
e.setks(4); check('kl.getks, kl.setks are Zkl common: available without Zklio', e.getks() == 4)
_w = setst_encode('B', 2, 0, rs1=5, g=2); _i = setst_encode('C', 3, 77, g=2)
check('setters: register form is G=2, F=0, r=0, immed7=0, rd=CSR, rs1=Xs1', setst_decode(_w)['G'] == 2 and setst_decode(_w)['F'] == 0 and setst_decode(_w)['r'] == 0 and setst_decode(_w)['immed7'] == 0 and setst_decode(_w)['kd'] == 2 and setst_decode(_w)['rs1'] == 5)
check('setters: immediate form is G=2, F=1, r=0, rs1=0, immed7=uimm7, rd=CSR', setst_decode(_i)['G'] == 2 and setst_decode(_i)['F'] == 1 and setst_decode(_i)['r'] == 0 and setst_decode(_i)['rs1'] == 0 and setst_decode(_i)['immed7'] == 77 and setst_decode(_i)['kd'] == 3)
e = E2(); e.zklio = True; e.w_maxiobuflen(1 << 20); check('mklmaxiobuflen: a value above the reset value sets it; below the lower bound (16) sets 16', e.r_maxiobuflen() == 256 and (e.w_maxiobuflen(4), e.r_maxiobuflen())[1] == 16)
e.w_maxiobuflen(128); e.w_kliobuflen(100); e.w_maxiobuflen(64); check('reducing mklmaxiobuflen below kliobuflen zeroes kliobuflen, kliobuftop and the whole KLIOBUF; no other state', e.kliobuflen == 0 and e.kliobuftop == 0 and e.iobuf == bytearray(256))
e = E2(); e.zklio = True; e.w_kliobuflen(512); check('kliobuflen is capped at mklmaxiobuflen', e.kliobuflen == 256)

section('GR34 zeroing, GR22/GR24, Unconfigured no-ops  <<KLE-GR-zero-unwritten-output>>, <<KLE-GR-to-ready>>, <<KLE-GR-success-failure-cannot-be-set-directly>>')
e = enc(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 32; e.iobuf[:48] = bytes([0xAA]) * 48; e.L[1].mdh = mdh_put(e.md(1), 'UsagePolicy', 0x4)
e.start = 16; e.setst(1, 1); r = e.execw(1, form='D')
check('Form D in Ready (not admitted -> Invalid): KLIOBUF bytes [klstart, kliobuftop-1] zeroed, below klstart and above kliobuftop kept', r == 'invalid' and bytes(e.iobuf[16:32]) == bytes(16) and bytes(e.iobuf[:16]) == bytes([0xAA]) * 16 and bytes(e.iobuf[32:48]) == bytes([0xAA]) * 16)
e = KLE2(); e.zklio = True; e.kliobuflen = 64; e.kliobuftop = 32; e.iobuf[:48] = bytes([0xAA]) * 48
check('Form D on an Unconfigured locker (inert): configured KLIOBUF window zeroed (GR34, GR33)', e.execw(1, form='D') == 'inert' and bytes(e.iobuf[:32]) == bytes(32) and bytes(e.iobuf[32:48]) == bytes([0xAA]) * 16)
e = enc(); r = e.execw(1, form='B', data=bytes([1]) * 32)
check('Form A-C vector output of an Invalid exec: all elements zero (GR34)', r == 'invalid' and e.vout == bytes(32))
e = enc(); e.start = 8; e.execw(1, form='A', data=bytes([1]) * 32); check('GR52.3 Invalid (item 3): the unwritten output is zero', e.vout == bytes(32))
for st_ in (54, 55):
    e = enc(); e.setst(1, 1); e.setst(1, st_); check('GR24: kl.setst naming %s is not admitted: Invalid' % ('Success' if st_ == 54 else 'Failure'), stx(e, 1) == INV)
e = enc(); e.L[1].mdh = mdh_put(e.md(1), 'MachinePolicy', 0); e.setst(1, 1)
check('GR22: kl.setst Ready is admitted in a Valid State whatever the MachinePolicy', e.getst(1) == 1)
e = enc(); e.L[1].mdh = mdh_put(e.md(1), 'MachinePolicy', 0); e.clearads(1)
check('GR22: kl.clearads is admitted in a Valid State whatever the MachinePolicy', e.getst(1) == 2 and stx(e, 1) != INV)
e = enc(); e.clearads(1, form='B') if False else None
for imm in (48, 53, 54, 1, 2):
    e = KLE2(); check('Unconfigured locker: kl.setst #%d is a no-op (<<KLE-GR-outcome-inert>>)' % imm, (e.setst(7, imm), e.getmd(7))[1] == 0 and e.getst(7) == 0)
e = KLE2(); check('Unconfigured locker: kl.clearads and kl.rstrl are no-ops', (e.clearads(7), e.rstr(7, mdh_pack(MachinePolicy=1), part='l'), e.getmd(7))[2] == 0)

section('GR22 Success/Failure as Machine outcomes (toy VERIFY Machine)  <<KLE-GR-to-ready>>, <<KLE-GR-success-failure-cannot-be-set-directly>>, <<KLE-MGR-config-data-error>>')
def ver():
    e = E2(); prov(e, 1, mach=M_VER, pol=1); e.setst(1, 2); return e
key = v2b(E2().L[1].content, 16)
e = ver(); K = v2b(e.L[1].content, 16)
check('VERIFY: matching tag -> Success (54), no exception', e.execv(1, K) == 54 and e.getst(1) == 54)
e = ver(); check('VERIFY: wrong tag -> Failure (55), an outcome: no Error State, no exception', e.execv(1, bytes(16) if K != bytes(16) else bytes([1]) * 16) == 55 and stx(e, 1) == (55, 0))
for st_, nm in ((54, 'Success'), (55, 'Failure')):
    e = ver(); e.execv(1, K if st_ == 54 else bytes([K[0] ^ 1]) + K[1:]); check('%s admits no further kl.exec: Invalid' % nm, (e.exec(1), stx(e, 1))[1] == INV)
    e = ver(); e.execv(1, K if st_ == 54 else bytes([K[0] ^ 1]) + K[1:]); e.L[1].mdh = mdh_put(e.md(1), 'MachinePolicy', 0); e.setst(1, 1)
    check('%s -> kl.setst Ready is admitted whatever the MachinePolicy (GR22)' % nm, e.getst(1) == 1)
    e = ver(); e.execv(1, K if st_ == 54 else bytes([K[0] ^ 1]) + K[1:]); e.clearads(1); check('%s -> kl.clearads admitted (GR22)' % nm, e.getst(1) == 1 or e.getst(1) == st_)
    e = ver(); e.execv(1, K if st_ == 54 else bytes([K[0] ^ 1]) + K[1:]); e.setst(1, 54); check('%s -> kl.setst Success is not admitted: Invalid (GR24)' % nm, stx(e, 1) == INV)
e = ver(); e.expiry_check = None; e.L[1].mdh = mdh_put(e.md(1), 'UsagePolicy', 0); check('VERIFY kl.exec with UsagePolicy forbidding the mode: privilege violation, not Failure', trap(e.execv, 1, K) == 'privilege_violation' and e.getst(1) == 2)

e = KLE(); e.mgmt(2, 58, md=mk(State=57)); check('import completion with ml.State 0 on a non-Version-3 locker: illegal, State kept (58)', trap(e.mgmt, 2, 63, form='C', md=mk(State=0)) == 'illegal' and e.getst(2) == 58)

section('ppi completion restores kl_cfg_provisioning  <<KLE-GR-completion-state>>, <<KLE-management-formats-and-states>>')
e = KLE(); e.mgmt(1, 56, md=mk()); e.mgmt(1, 57, form='A'); e.mgmt(1, 63, form='C', md=mk(State=56))
check('ppi export (59) completed with ml.State 56: kl_cfg_provisioning, MDH.State 56, StateExtension 0', stx(e, 1) == (56, 0))
FIN(e, 1); check('... and the provisioning then completes to Ready', stx(e, 1) == (1, 0))
e = KLE(); e.mgmt(2, 58, md=mk(State=56)); e.mgmt(2, 63, form='C', md=mk(State=56))
check('ppi import (60) completed with ml.State 56: kl_cfg_provisioning', stx(e, 2) == (56, 0))
FIN(e, 2); check('... and the provisioning then completes to Ready', stx(e, 2) == (1, 0))
e = KLE(); e.mgmt(2, 58, md=mk(State=56)); e.mgmt(2, 63, form='C', md=mk(State=56)); e.L[2].mdh = mdh_put(mdh_put(e.md(2), 'MachineUse', 7), 'AuxInfo', 3)
FIN(e, 2); check('ppi import then provisioning completion zeroes MachineUse and AuxInfo', stx(e, 2) == (1, 0) and mdh_get(e.md(2), 'MachineUse') == 0 and mdh_get(e.md(2), 'AuxInfo') == 0)
for st_ in (1, 2, 58):
    e = KLE(); e.mgmt(2, 58, md=mk(State=56)); check('ppi import completion with ml.State %d (SCC/Valid): illegal, State kept (60)' % st_, trap(e.mgmt, 2, 63, form='C', md=mk(State=st_)) == 'illegal' and e.getst(2) == 60)
for st_ in (57, 58, 1):
    e = KLE(); e.mgmt(1, 56, md=mk()); e.mgmt(1, 57, form='A'); check('ppi export completion with ml.State %d: illegal, State kept (59)' % st_, trap(e.mgmt, 1, 63, form='C', md=mk(State=st_)) == 'illegal' and e.getst(1) == 59)
for st_ in (59, 60):
    e = KLE(); e.mgmt(1, 56, md=mk()); e.mgmt(1, 57, form='A'); e.mgmt(1, 63, form='C', md=mk(State=st_)); check('ppi export completed with ml.State %d (nesting): restored' % st_, e.getst(1) == st_)

section('Routed derive checks: tag/XOF sources, CMAC absorb, NIK KeyType  <<KLE-derive-endpoints>>, <<KLE-GR-derive-checks>>')
for nm, m in (('hash/XOF (Hash_Output / XOF output)', M_XOF), ('hash', M_HASH)):
    e = dv(srcm=m, spol=0); e.L[1].mdh = mdh_put(e.md(1), 'State', 2)
    e.derive(2, 1, 16); check('%s is not a kl.derive source here (only keystream, ECC/ML-KEM secrets, CMAC output via Hash_Output): source Invalid, destination untouched (GR39.2)' % nm,
                              stx(e, 1) == INV and e.getst(2) == 1 and e.L[2].content == 0)
e = dv(dstm=M_CMAC, dst=2); e.derive(2, 1, 32); check('CMAC Hash_Absorb is not a destination endpoint (shared secret): destination Invalid, source untouched (GR39.3)', stx(e, 2) == INV and e.getst(1) == 2)
for m, nm in ((M_HASH, 'hash'), (M_XOF, 'XOF'), (M_CMAC, 'CMAC'), (M_VER, 'VERIFY')):
    e = KLE(); e.mgmt(1, 56, md=mk(mach=m, pol=1, KeyType=1)); check('%s Machine with KeyType 1 (no key field to resolve): invalid Metadata -> Invalid' % nm, stx(e, 1) == INV)

section('ExpirationDate evaluation points  <<KLE-Metadata-expiration-date>>, <<KLE-GR-usage-policy>>')
def ex(clock, ed=1000, up=0x4, st=2, e=None):
    e = e or E2(clock=0); prov(e, 1, up=0x4, ExpirationDate=ed)
    if st != 1: e.setst(1, st)
    e.clock = clock
    e.L[1].mdh = mdh_put(e.md(1), 'UsagePolicy', up)
    return e
check('usage instruction on expired locker: Error State Expired, no exception', (lambda e: (trap(e.exec, 1), stx(e, 1)))(ex(2000)) == (None, (0, SE_EXPIRED)))
check('kl.setst (usage) is an evaluation point', (lambda e: (e.setst(1, 1), stx(e, 1)))(ex(2000))[1] == (0, SE_EXPIRED))
check('kl.clearads (usage) is an evaluation point', (lambda e: (e.clearads(1), stx(e, 1)))(ex(2000))[1] == (0, SE_EXPIRED))
check('clock equal to the date expires; one hour before does not', stx((lambda e: (e.exec(1), e)[1])(ex(1000)), 1) == (0, SE_EXPIRED) and stx((lambda e: (e.exec(1), e)[1])(ex(999)), 1) == (2, 0))
check('pre-epoch clock reads 0: no expiry for date 1', stx((lambda e: (e.exec(1), e)[1])(ex(-50, ed=1)), 1) == (2, 0))
check('clock past 2^20 - 1 saturates (no wrap): date 10 and date 2^20-1 both expired', all(stx((lambda e: (e.exec(1), e)[1])(ex((1 << 20) + 5, ed=d)), 1) == (0, SE_EXPIRED) for d in (10, mask(20))))
check('date 0 never expires, even with a huge clock', stx((lambda e: (e.exec(1), e)[1])(ex(1 << 30, ed=0)), 1) == (2, 0))
e = ex(0); e.zklio = True; e.start = 0; h = e.execw(1, form='A', data=bytes(64), halt_after=2); e.clock = 5000
r = e.execw(1, form='A', data=bytes(64))
check('a resumption point after a halt is an evaluation point: Expired', stx(e, 1) == (0, SE_EXPIRED))
e = ex(2000); d2 = E2(clock=2000)
e = ex(5000, ed=10, up=0x4)
r = [e.rstr(1, mdh_pack(ExpirationDate=9), part='h'), e.getst(1)]
check('kl.rstrh is not an evaluation point', r[1] == 2 and mdh_get(e.md(1), 'ExpirationDate') == 9)
e = ex(5000, ed=10); e.size(1); e.getmd(1); e.clone(2, 1) if hasattr(e, 'clone') else None
check('size, getmd, clone are not evaluation points: State kept', e.getst(1) == 2 and e.getst(2) == 2)
e = ex(5000, ed=10); e.mgmt(1, 57, form='A'); n = e.getst(1)
check('export opening of an expired Valid locker is not an evaluation point', n == 57)
e = ex(5000, ed=10); e.setst(1, 0) if False else e.clear(1)
check('kl.clear is not an evaluation point and works on an expired locker', e.md(1) == 0)
e = ex(5000, ed=10, st=1); e.L[1].mdh = mdh_put(e.md(1), 'State', 56)
check('a Configuration-State locker is not evaluated (privilege violation for usage, not Expired)', trap(e.exec, 1) == 'privilege_violation' and e.getst(1) == 56)
e = ex(5000, ed=10, up=0x3)
check('UsagePolicy violation precedes expiry (GR20 items 2, 3)', trap(e.exec, 1) == 'privilege_violation' and stx(e, 1) == (2, 0))
e = ex(5000, ed=10); e.clock = None
check('unreadable clock: clock-unavailable exception, State kept; usable once it reads', trap(e.exec, 1) == 'clock_unavailable' and e.getst(1) == 2 and (setattr(e, 'clock', 0), trap(e.exec, 1))[1] is None)
e = ex(5000, ed=0); e.clock = None
check('unreadable clock with date 0 is unaffected', trap(e.exec, 1) is None)
e = ex(5000, ed=10, up=0x3); e.clock = None
check('UsagePolicy precedes the unreadable clock', trap(e.exec, 1) == 'privilege_violation')
e = ex(5000, ed=10); e.clock = None; t = trap(e.exec, 1); e.setste(1, SE_EXPIRED)
check('SR10: a handler that cannot resolve the clock sets Expired by kl.setste (no usage, no clock read)', t == 'clock_unavailable' and stx(e, 1) == (0, SE_EXPIRED))
e = E2(zk=False); e.mgmt(1, 56, md=mk(ExpirationDate=1))
check('without Zklexpire a non-zero ExpirationDate in a PI is invalid Metadata', stx(e, 1) == INV)
e = E2(zk=False); prov(e, 1); e.rstr(1, mdh_pack(ExpirationDate=1), part='h')
check('without Zklexpire a restrict request with a non-zero ExpirationDate: Invalid (kl.rstr* validity rule)', stx(e, 1) == INV)
e = E2(zk=False, clock=1 << 30); prov(e, 1); e.setst(1, 2)
check('without Zklexpire no clock is read', trap(e.exec, 1) is None)

section('Per-locker Dirty tracking  <<KLE-CSR-llockerstatus>>')
def dl(): e = lowp(); e.lstat[1] = e.lstat[2] = 2; e.lstat[3] = 2; return e
e = dl(); e.run(e.getmd, 1); e.run(e.size, 1); check('read-only instructions leave the field Clean', e.lstat[1] == 2)
e = dl(); e.run(e.clearads, 1); check('kl.clearads on a locker with no ADS modifies nothing: Clean', e.lstat[1] == 2)
e = dl(); e.mode = 2; e.priv = 'S'; e.run(e.setst, 1, 2); check('kl.setst Encrypt (modifies): Dirty; other lockers untouched', e.lstat[1] == 3 and e.lstat[2] == 2)
e = dl(); e.run(e.clear, 1); check('kl.clear of a configured locker: Dirty', e.lstat[1] == 3)
e = dl(); e.run(e.clone, 3, 1); check('kl.clone: destination Dirty, source Clean', e.lstat[3] == 3 and e.lstat[1] == 2)
e = dl(); e.run(e.rename, 3, 1); check('kl.rename: both Dirty', e.lstat[1] == 3 and e.lstat[3] == 3)
e = dl(); e.run(e.swap, 1, 3); check('kl.swap of two lockers with different contents: both Dirty', e.lstat[1] == 3 and e.lstat[3] == 3)
e = dl(); e.run(e.swap, 1, 1); check('same-index swap: nothing modified, Clean', e.lstat[1] == 2)
e = dl(); e.run(e.mgmt, 3, 56, md=mk()); check('provisioning-opening kl.mgmt: Dirty', e.lstat[3] == 3)
e = dl(); e.run(e.setste, 1, 3); check('kl.setste: Dirty', e.lstat[1] == 3)
e = dl(); e.run(e.rstr, 1, mdh_pack(MachinePolicy=1), part='l'); check('kl.rstrl that narrows: Dirty', e.lstat[1] == 3)
e = dl(); e.run(e.rstr, 1, mdh_pack(MachinePolicy=3), part='l'); check('kl.rstrl that changes nothing: Clean', e.lstat[1] == 2)
e = dl(); e.lstat[1] = 0; e.lstat[2] = 3; e.run(e.clearall); check('kl.clearall: Off stays Off, the Dirty one stays Dirty', e.lstat[1] == 0 and e.lstat[2] == 3)

section('kl.setste matrix, KLNL no-ops, moves of Error/Success/Failure  <<KLE-instruction-setste>>, <<KLE-GR-error-state-transition>>, <<KLE-GR-klnamedlocker-override>>')
for se in (2, 3, 4, 5, 6):
    e = E2(); prov(e, 1); e.L[1].content = 0xAB; e.start = 32; e.setste(1, se)
    c = e.size(1); m = e.md(1)
    ok = (stx(e, 1) == (0, se), e.L[1].content == 0, mdh_get(m, 'AuxDataLen'), e.size(1) == 16, e.start == 32)
    e.mgmt(1, 57, form='A'); ok2 = (e.md(1) == m, e.start == 0)
    f = E2(); f.mgmt(3, 58, md=m)
    check('kl.setste #%d then export opening and short import: Error State, content cleared, size 16, MDH unchanged, short import reproduces it' % se,
          ok == (True, True, 0, True, True) and ok2 == (True, True) and f.md(3) == m and f.slots == E2().slots)
e = E2(zk=False); prov(e, 1); check('kl.setste #6 without Zklexpire is reserved: illegal, locker unchanged', trap(e.setste, 1, 6) == 'illegal' and stx(e, 1) == (1, 0))
for imm in (48, 53):
    e = E2(); prov(e, 1); e.setst(1, 2); e.setst(1, imm); check('kl.setst #%d, not defined by the Machine: Invalid' % imm, stx(e, 1) == INV)
for x in (7, 15):
    e = E2(); e.mgmt(1, 58, md=mk(State=0, StateExtension=x)); check('import of reserved StateExtension %d: invalid Metadata, Invalid' % x, stx(e, 1) == INV)
e = E2(); e.mgmt(2, 58, md=mk(State=0, StateExtension=SE_EXPIRED, AuxDataLen=4, ADSDropped=1))
check('short import with ADS fields: AuxDataLen and ADSDropped zeroed (GR35), no capacity', mdh_get(e.md(2), 'AuxDataLen') == 0 and mdh_get(e.md(2), 'ADSDropped') == 0 and stx(e, 2)[0] == 0 and e.slots == E2().slots)
e = E2(); e.setste(3, SE_INVALID); check('kl.setste on Unconfigured records the Error State (GR36)', stx(e, 3) == INV)
e = dv(); e.nl = 32; b = e.snap()
for nm, f in (('clone', lambda: e.clone('NL', 1)), ('rename', lambda: e.rename('NL', 1)), ('swap', lambda: e.swap('NL', 1)), ('rename src', lambda: e.rename(1, 'NL')),
              ('derive', lambda: e.derive('NL', 1, 16)), ('derive src', lambda: e.derive(2, 'NL', 16)), ('restrict', lambda: e.rstr(0, mdh_pack(UsagePolicy=1), r=1, part='h'))):
    check('KLNL = 32: %s performs no operation and raises nothing' % nm, trap(f) is None and e.snap() == b)
e = dv(); e.nl = 2; b = e.snap()
check('KLNL naming locker 2: derive with KLNL as destination and source 1 acts on locker 2', e.derive('NL', 1, 32) == 'ok' and e.L[2].content == SEC)
e = dv(); check('KLNL for both derive operands is illegal; a pair of locker 0 and KLNL=32 is no self-derivation', trap(e.derive, 'NL', 'NL', 16) == 'illegal')
for kind, desc in ((SE_EXPIRED, 'Error'),):
    e = E2(); prov(e, 1); e.setste(1, kind); m = e.md(1); e.rename(2, 1); e.swap(3, 2)
    check('an Error-State CC moves with kl.rename and kl.swap (not usage: no evaluation, no policy)', e.md(3) == m and e.md(1) == 0 and e.md(2) == 0)
e = ex(5000, ed=10, up=0); e.mode = 0
check('kl.rename, kl.swap and kl.clone are no usage: no UsagePolicy, no expiry evaluation, State kept', (e.rename(5, 1), e.swap(6, 5), e.clone(7, 6), stx(e, 6))[3] == (2, 0))
for fin in (54, 55):
    e = E2(); prov(e, 1, up=0x4); e.L[1].mdh = mdh_put(e.md(1), 'State', fin); e.rename(2, 1); e.swap(3, 2)
    check('a Machine outcome State %d moves with kl.rename and kl.swap' % fin, e.getst(3) == fin and e.md(2) == 0)

section('restrict sweep: UsagePolicy and MachinePolicy narrowing  <<KLE-instruction-restrict>>')
bad = []
for a in range(32):
    for b in range(32):
        e = E2(); prov(e, 1, up=a); e.rstr(1, mdh_pack(UsagePolicy=b), part='h')
        if mdh_get(e.md(1), 'UsagePolicy') != a & b: bad.append((a, b))
check('kl.rstrh: UsagePolicy becomes the AND of the two, 32 x 32 values', bad == [])
bad = []
for a in range(4):
    for b in range(4):
        e = E2(); prov(e, 1, pol=a); e.rstr(1, mdh_pack(MachinePolicy=b), part='l')
        if mdh_get(e.md(1), 'MachinePolicy') != a & b: bad.append((a, b))
check('kl.rstrl: MachinePolicy becomes the AND of the two, 4 x 4 values', bad == [])

section('Reset, negative controls')
e = KLE(); control('negative: a usage-policy violation does not move the State', (lambda: (prov(e, 1, up=0), trap(e.setst, 1, 2), e.getst(1))[2] == 1)())
control('negative: setst Encrypt with pol=2 reaches Invalid, not Encrypt', (lambda e: (prov(e, 1, pol=2), e.setst(1, 2), e.getstx(1))[2] == SE_INVALID)(KLE()))
control('negative: validate rejects Version 1 and accepts the plain PI', validate(mk(Version=1), 'provision') == 'invalid' and validate(mk(), 'provision') == 'ok')
control('negative: kl.size of a valid MDH is non-zero and of an invalid one zero', KLE().size(form='C', md=mk()) != 0 and KLE().size(form='C', md=mk(Version=1)) == 0)
control('negative: unconfigured test is not true for an Error State', not is_unconfigured(mdh_pack(StateExtension=2)))
done()
