// ATF step 3: reject missing, noninteger/out-of-range scores and unknown ratings.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new VRRiskDataHealth().run('values');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health valid scores and ratings', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
