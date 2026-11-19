From Paco Require Import paco.
From PromisingLib Require Import Basic Language Loc Event.
From PromisingSEQ Require Import ITreeLang NoMix Configuration Behavior SequentialITree SequentialCompatibility OptimizerAdequacy.
From O03 Require Import Cases.
Set Printing Width 1000000.
Set Printing Depth 1000000.

(* A conditional ORIGINAL-MODEL contract. It is not a C/Linux translation proof.
   All context and no-mixed-access premises from OptimizerAdequacy remain. *)
Definition instance (source result: block) : Prop :=
 forall (loc_na loc_at: Loc.t -> Prop),
 (forall loc, loc_na loc -> loc_at loc -> False) ->
 forall A (ctx_seq: itree MemE.t Const.t -> itree MemE.t A)
 (ctx_ths: Threads.syntax) (tid: Ident.t),
 @itree_context loc_na loc_at Const.t A ctx_seq ->
 nomix loc_na loc_at _ ((lang Const.t).(Language.init) (eval_lang source)) ->
 nomix loc_na loc_at _ ((lang Const.t).(Language.init) (eval_lang result)) ->
 (forall tid lang syn, IdentMap.find tid ctx_ths = Some (existT _ lang syn) ->
     nomix loc_na loc_at lang (lang.(Language.init) syn)) ->
 behaviors Configuration.step
   (Configuration.init (IdentMap.add tid (existT _ (lang A) (ctx_seq (eval_lang result))) ctx_ths))
 <2= behaviors Configuration.step
   (Configuration.init (IdentMap.add tid (existT _ (lang A) (ctx_seq (eval_lang source))) ctx_ths)).

Theorem rr_instance : instance rr_input rr_expected.
Proof.
 rewrite <- rr_actual_output. unfold instance, rr_output. intros.
 eapply RRforwarding_sound; eauto.
Qed.
Theorem wr_instance : instance wr_input wr_expected.
Proof.
 rewrite <- wr_actual_output. unfold instance, wr_output. intros.
 eapply WRforwarding_sound; eauto.
Qed.
Theorem dse_instance : instance dse_input dse_expected.
Proof.
 rewrite <- dse_actual_output. unfold instance, dse_output. intros.
 eapply DeadStoreElim_sound; eauto.
Qed.

Redirect "premises-instance" Print instance.
Redirect "premises-rr" Check @RRforwarding_sound.
Redirect "premises-wr" Check @WRforwarding_sound.
Redirect "premises-dse" Check @DeadStoreElim_sound.
Redirect "premises-licm-alternate" Check @LICM_LoadIntro_sound.
Redirect "assumptions-rr" Print Assumptions RRforwarding_sound.
Redirect "assumptions-wr" Print Assumptions WRforwarding_sound.
Redirect "assumptions-dse" Print Assumptions DeadStoreElim_sound.
Redirect "assumptions-licm-alternate" Print Assumptions LICM_LoadIntro_sound.
Redirect "assumptions-rr-instance" Print Assumptions rr_instance.
Redirect "assumptions-wr-instance" Print Assumptions wr_instance.
Redirect "assumptions-dse-instance" Print Assumptions dse_instance.
