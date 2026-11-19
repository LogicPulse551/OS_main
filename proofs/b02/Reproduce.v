Require Import Maps Integers Event Syntax Semantics CorrectOpt Behavior Configuration ww_RF.
Require Import ConstProp ConstPropProof CSE CSEProof DCE DCEProof LICM LICMProof VerifiedOpt.
Require Import Cases Evaluation.
Set Printing Width 1000000.
Set Printing Depth 1000000.

(* CONDITIONAL original-model contracts. Native extraction/runtime is trusted
   separately; its output checks are not kernel-checked equalities. *)
Definition instance (lo:Ordering.LocOrdMap) (source result:Code) : Prop :=
 forall fs ctid,
 @ww_rf rtl_lang lo fs source ctid -> @Configuration.safe rtl_lang lo fs source ctid ->
 (forall behs, @prog_behaviors rtl_lang fs result ctid lo behs -> @prog_behaviors rtl_lang fs source ctid lo behs) /\
 @ww_rf rtl_lang lo fs result ctid /\ @Configuration.safe rtl_lang lo fs result ctid.
Lemma connect (opt:Optimizer rtl_lang) (H:Correct opt) lo source result
 (APPLIED:opt lo source=Some result) : instance lo source result.
Proof. unfold instance. intros. eapply H; eauto. Qed.
Theorem cp_instance : instance non_atomic cp_input cp_expected.
Proof. eapply connect; [exact correct_constprop | exact cp_actual_output]. Qed.
Theorem cse_instance result (APPLIED:cse_output=Some result) : instance non_atomic cse_input result.
Proof. eapply connect; [exact correct_cse | exact APPLIED]. Qed.
Theorem dce_instance result (APPLIED:dce_output=Some result) : instance non_atomic dce_input result.
Proof. eapply connect; [exact correct_dce | exact APPLIED]. Qed.
Theorem licm_instance result (APPLIED:licm_output=Some result) : instance non_atomic licm_input result.
Proof. eapply connect; [exact correct_licm | exact APPLIED]. Qed.
Redirect "premises" Print Correct.
Redirect "instance-premises" Print instance.
Redirect "assumptions-cp" Print Assumptions correct_constprop.
Redirect "assumptions-cse" Print Assumptions correct_cse.
Redirect "assumptions-dce" Print Assumptions correct_dce.
Redirect "assumptions-licm" Print Assumptions correct_licm.
Redirect "assumptions-final" Print Assumptions Correct_optimizers.
Redirect "assumptions-cp-instance" Print Assumptions cp_instance.
Redirect "assumptions-cse-instance" Print Assumptions cse_instance.
Redirect "assumptions-dce-instance" Print Assumptions dce_instance.
Redirect "assumptions-licm-instance" Print Assumptions licm_instance.
