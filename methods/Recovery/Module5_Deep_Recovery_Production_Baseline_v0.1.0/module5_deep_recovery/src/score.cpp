// Evidence scoring is implemented in detector.cpp.
// Kept as a separate translation unit to reserve the commercial scoring layer
// for calibrated corpus-derived models without changing the scanner API.
namespace deep{int scoring_module_anchor(){return 1;}}
