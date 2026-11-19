Require Import Extraction ExtrOcamlBasic ExtrOcamlNatBigInt ExtrOcamlZBigInt.
Require Import Cases ConstProp CSE DCE LICM.
Extraction Language OCaml.
Extraction "original.ml" run_cp run_cse run_dce run_licm
 non_atomic atomic cp_input cse_input dce_input licm_input
 cp_boundary cse_boundary dce_boundary licm_boundary licm_print_boundary code_view.
