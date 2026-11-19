(* Team contract probes; run the ORIGINAL SEQ RR analysis unchanged.
   These are model programs, NOT a translation of regcache_lookup_reg. *)
From PromisingLib Require Import Basic Loc Event.
From PromisingSEQ Require Import ITreeLang RRforwarding.
Set Printing Width 1000000.
Definition l := RRforwarding.loc1.
Definition other := RRforwarding.loc2.
Definition a := RRforwarding.a.
Definition b := RRforwarding.b.
Definition c := RRforwarding.c.
Definition rd x p o := inst (Inst.load x p o).
Definition keep := cons (rd b l Ordering.na) nil.
Definition forwarded := cons (inst (Inst.assign b (Inst.expr_var a))) nil.

Definition same : block := cons (rd a l Ordering.na) keep.
Definition different_read : block := cons (rd a l Ordering.na) (cons (rd c other Ordering.na) keep).
Definition overwritten : block := cons (rd a l Ordering.na) (cons (inst (Inst.store l (Inst.expr_val Const.one) Ordering.na)) keep).
Definition acquired : block := cons (rd a l Ordering.na) (cons (rd c other Ordering.acqrel) keep).
Definition opaque_call : block := cons (rd a l Ordering.na) (cons (inst (Inst.syscall c Datatypes.nil)) keep).
Definition register_changed : block := cons (rd a l Ordering.na) (cons (inst (Inst.assign a (Inst.expr_val Const.one))) keep).
Definition branched : block := cons (rd a l Ordering.na)
 (cons (ite (Inst.expr_var c) (cons (inst (Inst.store l (Inst.expr_val Const.one) Ordering.na)) nil) nil) keep).

Theorem same_forwarded : RRfwd_opt_alg same = cons (rd a l Ordering.na) forwarded.
Proof. reflexivity. Qed.
Theorem different_read_forwarded : RRfwd_opt_alg different_read = cons (rd a l Ordering.na) (cons (rd c other Ordering.na) forwarded).
Proof. reflexivity. Qed.
Theorem overwritten_preserved : RRfwd_opt_alg overwritten = overwritten.
Proof. reflexivity. Qed.
Theorem acquired_preserved : RRfwd_opt_alg acquired = acquired.
Proof. reflexivity. Qed.
Theorem opaque_call_preserved : RRfwd_opt_alg opaque_call = opaque_call.
Proof. reflexivity. Qed.
Theorem register_changed_preserved : RRfwd_opt_alg register_changed = register_changed.
Proof. reflexivity. Qed.
Theorem branch_write_preserved : RRfwd_opt_alg branched = branched.
Proof. reflexivity. Qed.

Redirect "assumptions-same" Print Assumptions same_forwarded.
Redirect "assumptions-other-read" Print Assumptions different_read_forwarded.
Redirect "assumptions-store" Print Assumptions overwritten_preserved.
Redirect "assumptions-acquire" Print Assumptions acquired_preserved.
Redirect "assumptions-call" Print Assumptions opaque_call_preserved.
Redirect "assumptions-register" Print Assumptions register_changed_preserved.
Redirect "assumptions-branch" Print Assumptions branch_write_preserved.
Redirect "output-same" Eval vm_compute in RRfwd_opt_alg same.
Redirect "output-call" Eval vm_compute in RRfwd_opt_alg opaque_call.
