From PromisingLib Require Import Event.
From PromisingSEQ Require Import ITreeLang RRforwarding.
From O03 Require Import Cases.
(* Intentionally false: a load across an acquire may not reuse the older read. *)
Goal RRfwd_opt_alg rr_acquire_input =
 cons (inst (Inst.load RRforwarding.a RRforwarding.loc1 Ordering.na))
 (cons (inst (Inst.load RRforwarding.b RRforwarding.loc2 Ordering.acqrel))
 (cons (inst (Inst.assign RRforwarding.c (Inst.expr_var RRforwarding.a))) nil)).
Proof. reflexivity. Qed.
