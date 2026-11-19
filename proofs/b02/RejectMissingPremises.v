(* Expected to fail: the original conditional theorem is not unconditional. *)
Require Import Syntax Semantics Behavior Configuration ww_RF Cases Evaluation Reproduce.
Goal forall fs ctid,
 (forall behs, @prog_behaviors rtl_lang fs cp_expected ctid non_atomic behs ->
               @prog_behaviors rtl_lang fs cp_input ctid non_atomic behs) /\
 @ww_rf rtl_lang non_atomic fs cp_expected ctid /\
 @Configuration.safe rtl_lang non_atomic fs cp_expected ctid.
Proof.
 intros fs ctid.
 pose proof (cp_instance fs ctid) as H.
 exact H.
Qed.
