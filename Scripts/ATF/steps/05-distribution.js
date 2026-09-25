// ATF step 5: check all five percentage ranges and optional mean-score bounds.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new VRRiskDataHealth().run('distribution');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health rating distribution', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
