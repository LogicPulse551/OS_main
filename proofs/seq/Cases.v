(* Original SEQ algorithms and examples. No optimizer is reimplemented here. *)
From sflib Require Import sflib.
From PromisingLib Require Import Basic Loc Event.
From PromisingSEQ Require Import ITreeLang RRforwarding WRforwarding DeadStoreElim.
Set Printing Width 1000000.
Set Printing Depth 1000000.

Definition rr_input := RRforwarding.test0.
Definition rr_output := RRfwd_opt_alg rr_input.
Definition rr_expected := RRforwarding.test0'.
Definition wr_input := WRforwarding.test0.
Definition wr_output := WRfwd_opt_alg wr_input.
Definition wr_expected := WRforwarding.test0'.
Definition dse_input := DeadStoreElim.test0.
Definition dse_output := DSE_opt_alg dse_input.
Definition dse_expected := DeadStoreElim.test0'.

Theorem rr_actual_output : rr_output = rr_expected.
Proof. reflexivity. Qed.
Theorem wr_actual_output : wr_output = wr_expected.
Proof. reflexivity. Qed.
Theorem dse_actual_output : dse_output = dse_expected.
Proof. reflexivity. Qed.
Theorem rr_changed : rr_output <> rr_input.
Proof. discriminate. Qed.
Theorem wr_changed : wr_output <> wr_input.
Proof. discriminate. Qed.
Theorem dse_changed : dse_output <> dse_input.
Proof. discriminate. Qed.

(* Boundary cases exercise the author's dataflow joins and visibility rules. *)
Theorem rr_branch_join : RRfwd_opt_alg RRforwarding.test2 = RRforwarding.test2'.
Proof. reflexivity. Qed.
Theorem wr_branch_disagreement : WRfwd_opt_alg WRforwarding.test7 = WRforwarding.test7.
Proof. reflexivity. Qed.
Theorem wr_acquire_join : WRfwd_opt_alg WRforwarding.test8 = WRforwarding.test8.
Proof. reflexivity. Qed.
Theorem wr_selective_acquire : WRfwd_opt_alg WRforwarding.test9 = WRforwarding.test9'.
Proof. reflexivity. Qed.
Theorem dse_intervening_read : DSE_opt_alg DeadStoreElim.test1 = DeadStoreElim.test1.
Proof. reflexivity. Qed.
Theorem dse_release_loop : DSE_opt_alg DeadStoreElim.test3 = DeadStoreElim.test3.
Proof. reflexivity. Qed.
Theorem dse_release_acquire : DSE_opt_alg DeadStoreElim.test6 = DeadStoreElim.test6.
Proof. reflexivity. Qed.
Theorem dse_acquire_permitted : DSE_opt_alg DeadStoreElim.test4 = DeadStoreElim.test4'.
Proof. reflexivity. Qed.

(* Team boundary example: acquiring another location invalidates an older read. *)
Definition rr_acquire_input : block :=
 cons (inst (Inst.load RRforwarding.a RRforwarding.loc1 Ordering.na))
 (cons (inst (Inst.load RRforwarding.b RRforwarding.loc2 Ordering.acqrel))
 (cons (inst (Inst.load RRforwarding.c RRforwarding.loc1 Ordering.na)) nil)).
Theorem rr_acquire_preserved : RRfwd_opt_alg rr_acquire_input = rr_acquire_input.
Proof. reflexivity. Qed.

Redirect "input-rr" Eval vm_compute in rr_input.
Redirect "output-rr" Eval vm_compute in rr_output.
Redirect "input-wr" Eval vm_compute in wr_input.
Redirect "output-wr" Eval vm_compute in wr_output.
Redirect "input-dse" Eval vm_compute in dse_input.
Redirect "output-dse" Eval vm_compute in dse_output.
Redirect "assumptions-output-rr" Print Assumptions rr_actual_output.
Redirect "assumptions-output-wr" Print Assumptions wr_actual_output.
Redirect "assumptions-output-dse" Print Assumptions dse_actual_output.
