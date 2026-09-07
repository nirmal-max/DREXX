# Architecture

Source
  -> bounded region
  -> coarse stride scan
  -> anchor detector
  -> adaptive refinement
  -> filesystem validator
  -> evidence vector
  -> score
  -> overlap cluster
  -> ranked volume hypotheses
  -> resumable state / JSON

Evidence examples:
- boot signature
- sector-size plausibility
- cluster-size plausibility
- total-size consistency
- metadata location bounds
- backup boot evidence
- filesystem-specific fixed fields

The engine deliberately preserves several hypotheses if their evidence is
strong enough. The caller can later hand a selected hypothesis to Module 4.
